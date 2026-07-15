// SPDX-License-Identifier: GPL-2.0
/*
 * ela_kmod - embedded_linux_audit host inspection module.
 *
 * Exposes /dev/ela_physmem, a misc character device whose ioctl interface
 * (kmod/ela_ioctl.h) lets the agent read physical memory on hosts where
 * /dev/mem is absent or restricted (CONFIG_STRICT_DEVMEM). The interface is
 * designed to grow chipsec-style operations (MSR, PCI config, port I/O);
 * their ioctl numbers are already reserved in ela_ioctl.h.
 *
 * Portability: this file targets vendor kernels from 3.x through 6.x, so
 * kernel-API differences are guarded by LINUX_VERSION_CODE below and the
 * API surface is deliberately tiny (misc device + physical mapping only).
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/highmem.h>	/* kmap/kunmap for the RAM read/write path */
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/version.h>

/*
 * IS_ENABLED()/IS_BUILTIN()/IS_MODULE() arrived with <linux/kconfig.h> in 3.1
 * (and modern kbuild -includes it automatically). On older kernels — this
 * module builds back to 2.6 — they are undefined, so the `#if IS_ENABLED(...)`
 * include guards below fail to preprocess ("missing binary operator before
 * token"). Provide the upstream kconfig.h implementation when it is absent.
 */
#ifndef IS_ENABLED
#define __ARG_PLACEHOLDER_1 0,
#define __take_second_arg(__ignored, val, ...) val
#define __and(x, y)			___and(x, y)
#define ___and(x, y)			____and(__ARG_PLACEHOLDER_##x, y)
#define ____and(arg1_or_junk, y)	__take_second_arg(arg1_or_junk y, 0)
#define __or(x, y)			___or(x, y)
#define ___or(x, y)			____or(__ARG_PLACEHOLDER_##x, y)
#define ____or(arg1_or_junk, y)		__take_second_arg(arg1_or_junk 1, y)
#define __is_defined(x)			___is_defined(x)
#define ___is_defined(val)		____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk)	__take_second_arg(arg1_or_junk 1, 0)
#define IS_BUILTIN(option) __is_defined(option)
#define IS_MODULE(option) __is_defined(option##_MODULE)
#define IS_REACHABLE(option) __or(IS_BUILTIN(option), \
				__and(IS_MODULE(option), __is_defined(MODULE)))
#define IS_ENABLED(option) __or(IS_BUILTIN(option), IS_MODULE(option))
#endif

#ifdef CONFIG_PCI
# include <linux/pci.h>
#endif
/*
 * MTD/SPI support is gated on IS_BUILTIN, not IS_ENABLED: IS_ENABLED is also
 * true for =m, but those subsystems export their symbols (get_mtd_device,
 * spi_bus_type, ...) from loadable modules, not vmlinux. Building this
 * out-of-tree module against a kernel whose Module.symvers lacks them (the
 * builder only prepares the target kernel, it does not build its modules) then
 * fails at MODPOST with "undefined!". When MTD/SPI are modular or absent the
 * #else stubs below return -EOPNOTSUPP instead.
 */
#if IS_BUILTIN(CONFIG_SPI)
# include <linux/spi/spi.h>
#endif
/*
 * The MTD/NAND and SPI-flash dump paths use the mtd_read()/mtd_block_isbad()
 * accessor API, the mtd_info.ecc_strength field and the MTD_MLCNANDFLASH type,
 * all introduced around 3.4. Rather than shim that entire pre-3.4 MTD API, gate
 * the whole implementation on >= 3.4; older kernels (this module builds back to
 * 2.6) fall to the -EOPNOTSUPP stubs. Every MTD block keys off ELA_HAVE_MTD.
 */
#if IS_BUILTIN(CONFIG_MTD) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
# define ELA_HAVE_MTD 1
#endif
#ifdef ELA_HAVE_MTD
# include <linux/mtd/mtd.h>
#endif
/*
 * The USB hub port-power / descriptor paths need <linux/usb/ch11.h> (the USB 2.0
 * chapter-11 hub definitions), a public header only from ~2.6.39. Probe for it
 * and gate the USB implementation on its presence; older kernels (this module
 * builds back to 2.6) fall to the -EOPNOTSUPP stubs. Every USB block keys off
 * ELA_HAVE_USB.
 */
#if IS_ENABLED(CONFIG_USB)
# if defined(__has_include)
#  if __has_include(<linux/usb/ch11.h>)
#   define ELA_HAVE_USB 1
#  endif
# elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
#  define ELA_HAVE_USB 1
# endif
#endif
#ifdef ELA_HAVE_USB
# include <linux/usb.h>
# include <linux/usb/ch11.h>
# include <linux/delay.h>
#endif
#if IS_ENABLED(CONFIG_BLOCK) && IS_ENABLED(CONFIG_MMC_BLOCK) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
# include <linux/blkdev.h>
# include <linux/mmc/card.h>
# include <linux/major.h>
#endif
/*
 * The WLAN firmware-command injection shim reads the driver's call arguments
 * out of pt_regs via regs_get_kernel_argument(), which only exists from 4.20,
 * and uses round_up() (post-2.6.32). Gate the whole kprobe shim on >= 4.20;
 * older kernels (this module builds back to 2.6) fall to the -EOPNOTSUPP stub.
 */
#if IS_ENABLED(CONFIG_KPROBES) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
# include <linux/kprobes.h>
# include <linux/skbuff.h>
# include <linux/ptrace.h>
#endif

#include "ela_ioctl.h"

static void ela_copy_fixed_name(char *dst, size_t dst_len, const char *src);
/* Portable readq/writeq on 32-bit arches: split into two 32-bit accesses,
 * low word first (same order chipsec uses). 64-bit arches get native ops.
 * Upstream moved this wrapper from <asm-generic/...> to <linux/...> in 3.15,
 * and the asm-generic one only appeared in 3.4 — before that NEITHER header
 * exists, so we provide the split inline. Probe with __has_include where
 * available, else fall back to version checks. */
#if defined(__has_include)
# if __has_include(<linux/io-64-nonatomic-lo-hi.h>)
#  include <linux/io-64-nonatomic-lo-hi.h>
# elif __has_include(<asm-generic/io-64-nonatomic-lo-hi.h>)
#  include <asm-generic/io-64-nonatomic-lo-hi.h>
# else
#  define ELA_INLINE_IO64 1
# endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
# include <linux/io-64-nonatomic-lo-hi.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
# include <asm-generic/io-64-nonatomic-lo-hi.h>
#else
# define ELA_INLINE_IO64 1
#endif

/*
 * kvmalloc()/kvfree() are later additions — kvfree() arrived in 4.6, kvmalloc()
 * in 4.12 — but this module is built against kernels back to 2.6, where an
 * unguarded call is an implicit declaration (fatal under the kernel's
 * -Werror=implicit-function-declaration). Provide fallbacks with the same
 * semantics: try a contiguous kmalloc first (silently, __GFP_NOWARN), fall back
 * to vmalloc for large/failed allocations, and free whichever way it landed.
 * All of kmalloc/vmalloc/kfree/vfree/is_vmalloc_addr/__GFP_NOWARN exist in 2.6.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static inline void *kvmalloc(size_t size, gfp_t flags)
{
	void *p = kmalloc(size, flags | __GFP_NOWARN);

	if (!p)
		p = vmalloc(size);
	return p;
}
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
static inline void kvfree(const void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}
#endif

#if IS_ENABLED(CONFIG_BLOCK) && IS_ENABLED(CONFIG_MMC_BLOCK) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
#define ELA_MMC_MAX_MINORS 256U

static bool ela_emmc_disk_name(const char *name)
{
	const char *p;

	if (strncmp(name, "mmcblk", 6))
		return false;
	p = name + 6;
	if (!*p)
		return false;
	for (; *p; p++) {
		if (*p < '0' || *p > '9')
			return false;
	}
	return true;
}

static bool ela_bdev_is_emmc_user_area(struct block_device *bdev)
{
	struct device *parent;
	struct mmc_card *card;

	if (!bdev || bdev_is_partition(bdev) ||
	    !ela_emmc_disk_name(bdev->bd_disk->disk_name))
		return false;
	parent = disk_to_dev(bdev->bd_disk)->parent;
	if (!parent)
		return false;
	card = container_of(parent, struct mmc_card, dev);
	return mmc_card_mmc(card);
}

static struct file *ela_emmc_open(dev_t dev)
{
	struct file *file;

	file = bdev_file_open_by_dev(dev, BLK_OPEN_READ, NULL, NULL);
	if (IS_ERR(file))
		return file;
	if (!ela_bdev_is_emmc_user_area(file_bdev(file))) {
		bdev_fput(file);
		return ERR_PTR(-ENODEV);
	}
	return file;
}

static long ela_ioctl_emmc_get(unsigned long arg)
{
	struct ela_kmod_emmc_device req;
	u32 position = 0;
	u32 minor;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;

	for (minor = 0; minor < ELA_MMC_MAX_MINORS; minor++) {
		struct file *file;
		struct block_device *bdev;

		file = ela_emmc_open(MKDEV(MMC_BLOCK_MAJOR, minor));
		if (IS_ERR(file))
			continue;
		bdev = file_bdev(file);
		if (position++ != req.ordinal) {
			bdev_fput(file);
			continue;
		}
		req.major = MMC_BLOCK_MAJOR;
		req.minor = minor;
		req.logical_block_size = bdev_logical_block_size(bdev);
		req.pad = 0;
		req.size = bdev_nr_bytes(bdev);
		memset(req.disk_name, 0, sizeof(req.disk_name));
		ela_copy_fixed_name(req.disk_name, ELA_KMOD_EMMC_NAME_LEN,
				    bdev->bd_disk->disk_name);
		bdev_fput(file);
		if (copy_to_user((void __user *)arg, &req, sizeof(req)))
			return -EFAULT;
		return 0;
	}
	return -ENOENT;
}

static long ela_ioctl_emmc_read(unsigned long arg)
{
	struct ela_kmod_emmc_read req;
	struct file *file;
	void *buf;
	loff_t position;
	ssize_t got;
	long rc = 0;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION || req.pad ||
	    req.major != MMC_BLOCK_MAJOR || !req.buf || !req.length ||
	    req.length > ELA_KMOD_EMMC_MAX_READ ||
	    req.offset + req.length < req.offset)
		return -EINVAL;

	file = ela_emmc_open(MKDEV(req.major, req.minor));
	if (IS_ERR(file))
		return PTR_ERR(file);
	if (req.offset > bdev_nr_bytes(file_bdev(file)) ||
	    req.length > bdev_nr_bytes(file_bdev(file)) - req.offset) {
		rc = -EINVAL;
		goto out_file;
	}
	buf = kvmalloc((size_t)req.length, GFP_KERNEL);
	if (!buf) {
		rc = -ENOMEM;
		goto out_file;
	}
	position = (loff_t)req.offset;
	got = kernel_read(file, buf, (size_t)req.length, &position);
	if (got < 0)
		rc = got;
	else if ((u64)got != req.length)
		rc = -EIO;
	else if (copy_to_user((void __user *)(uintptr_t)req.buf, buf,
			      (size_t)req.length))
		rc = -EFAULT;
	kvfree(buf);
out_file:
	bdev_fput(file);
	return rc;
}
#else
static long ela_ioctl_emmc_get(unsigned long arg)
{
	(void)arg;
	return -EOPNOTSUPP;
}

static long ela_ioctl_emmc_read(unsigned long arg)
{
	(void)arg;
	return -EOPNOTSUPP;
}
#endif

#ifdef ELA_INLINE_IO64
/* Pre-3.4 kernels ship no io-64-nonatomic header. Define the lo-hi split
 * accessors ourselves, but only where the arch hasn't already provided them
 * (64-bit arches define readq/writeq natively in asm/io.h). */
# ifndef readq
static inline u64 readq(const volatile void __iomem *addr)
{
	const volatile u32 __iomem *p = addr;

	return (u64)readl(p) | ((u64)readl(p + 1) << 32);
}
# endif
# ifndef writeq
static inline void writeq(u64 val, volatile void __iomem *addr)
{
	volatile u32 __iomem *p = addr;

	writel((u32)val, p);
	writel((u32)(val >> 32), p + 1);
}
# endif
#endif

/* memremap() replaced cached ioremap variants in 4.3 (declared in io.h). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
# define ELA_HAVE_MEMREMAP 1
#else
# define ELA_HAVE_MEMREMAP 0
#endif

/* ioremap_nocache() was removed in 5.6; plain ioremap() is uncached since. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
# define ela_ioremap_uncached(addr, size) ioremap(addr, size)
#else
# define ela_ioremap_uncached(addr, size) ioremap_nocache(addr, size)
#endif

/* Cached ioremap for the pre-memremap (< 4.3) path. The generic ioremap_cache()
 * spelling isn't available on every old arch: ARM only carried ioremap_cached()
 * through this era (it gained the generic alias later and dropped the old name
 * in 5.x). Key on the arch rather than a version boundary, which is stable. */
#if !ELA_HAVE_MEMREMAP
# ifdef CONFIG_ARM
#  define ela_ioremap_cached(addr, size) ioremap_cached(addr, size)
# else
#  define ela_ioremap_cached(addr, size) ioremap_cache(addr, size)
# endif
#endif

/* Per-mapping window: large reads are served in page-aligned chunks of this
 * size so a huge request never pins a huge contiguous mapping, and the bounce
 * buffer stays one kmalloc'd page-order allocation. */
#define ELA_MAP_WINDOW (1UL << 20) /* 1 MiB */
#define ELA_BOUNCE_SIZE PAGE_SIZE

/* Per-open-file state: physical allocations made through ELA_IOC_ALLOC_PHYS,
 * mutex-protected and released automatically when the fd closes. (chipsec
 * keeps these on an unlocked global list freed only at module unload; both
 * are bugs we deliberately do not port.) */
struct ela_file_state {
	struct mutex lock;
	struct list_head allocations;
};

struct ela_phys_alloc {
	struct list_head node;
	phys_addr_t phys;
	unsigned long virt;
	unsigned int order;
};

#ifdef ELA_HAVE_MTD
struct ela_nand_entry {
	struct list_head node;
	int mtd_index;
};

static LIST_HEAD(ela_nand_entries);
static DEFINE_MUTEX(ela_nand_lock);

static bool ela_mtd_is_nand(const struct mtd_info *mtd)
{
	return mtd->type == MTD_NANDFLASH ||
	       mtd->type == MTD_MLCNANDFLASH;
}

static void ela_nand_mtd_add(struct mtd_info *mtd)
{
	struct ela_nand_entry *entry;

	if (!ela_mtd_is_nand(mtd))
		return;
	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;
	entry->mtd_index = mtd->index;
	mutex_lock(&ela_nand_lock);
	list_add_tail(&entry->node, &ela_nand_entries);
	mutex_unlock(&ela_nand_lock);
}

static void ela_nand_mtd_remove(struct mtd_info *mtd)
{
	struct ela_nand_entry *entry;
	struct ela_nand_entry *tmp;

	mutex_lock(&ela_nand_lock);
	list_for_each_entry_safe(entry, tmp, &ela_nand_entries, node) {
		if (entry->mtd_index == mtd->index) {
			list_del(&entry->node);
			kfree(entry);
			break;
		}
	}
	mutex_unlock(&ela_nand_lock);
}

static struct mtd_notifier ela_nand_mtd_notifier = {
	.add = ela_nand_mtd_add,
	.remove = ela_nand_mtd_remove,
};

static void ela_nand_entries_clear(void)
{
	struct ela_nand_entry *entry;
	struct ela_nand_entry *tmp;

	mutex_lock(&ela_nand_lock);
	list_for_each_entry_safe(entry, tmp, &ela_nand_entries, node) {
		list_del(&entry->node);
		kfree(entry);
	}
	mutex_unlock(&ela_nand_lock);
}
#endif

/* One mapped window of physical memory plus the bookkeeping to unmap it with
 * the API that created it (memunmap vs iounmap). */
struct ela_phys_map {
	void __iomem *base;   /* mapping base (page-aligned) */
	void __iomem *va;     /* first requested byte within the mapping */
	bool used_memremap;
};

/*
 * True only when every page the mapping would cover is real RAM (has a struct
 * page). The default cached path must not ioremap device MMIO or unbacked
 * physical holes: reading those faults the CPU (on ARM, an imprecise external
 * abort that takes the machine down), which is exactly how a stray
 * `memread 0x<not-ram>` crashes the device. Callers that genuinely want device
 * memory opt in with ELA_KMOD_READ_F_UNCACHED and accept the risk.
 */
static bool ela_range_is_ram(u64 phys, size_t len)
{
	unsigned long pfn = (unsigned long)(phys >> PAGE_SHIFT);
	unsigned long end_pfn = (unsigned long)((phys + len - 1) >> PAGE_SHIFT);

	if (!len)
		return false;
	for (; pfn <= end_pfn; pfn++) {
		if (!pfn_valid(pfn))
			return false;
	}
	return true;
}

/*
 * Map `len` bytes at physical `phys` UNCACHED for device/MMIO access. RAM is
 * never mapped here — it is already in the kernel's linear map and a second,
 * differently-cached ioremap alias of it is architecturally illegal on ARMv6+
 * (and crashes the machine); RAM goes through kmap in ela_do_phys_io instead.
 * This path is reached only for ELA_KMOD_READ_F_UNCACHED. Page-aligned around
 * the request; callers keep len within ELA_MAP_WINDOW. 0 + *map, or -ENXIO.
 */
static int ela_map_phys(u64 phys, size_t len, struct ela_phys_map *map)
{
	/* Not PAGE_MASK: that is an unsigned long, which on 32-bit kernels
	 * with 64-bit physical addresses (PAE/LPAE) would clear the high
	 * word of the address when widened. */
	u64 aligned = phys & ~(u64)(PAGE_SIZE - 1);
	size_t offset = phys - aligned;
	size_t map_len = offset + len;
	void __iomem *va;

	map->used_memremap = false;

	/* On kernels with a 32-bit phys_addr_t, an address beyond 4 GiB would
	 * silently truncate at the mapping call; refuse it instead. */
	if (aligned != (u64)(phys_addr_t)aligned ||
	    map_len != (size_t)(phys_addr_t)map_len)
		return -ENXIO;

	va = ela_ioremap_uncached(aligned, map_len);
	if (!va)
		return -ENXIO;

	map->base = va;
	map->va = va + offset;
	return 0;
}

static void ela_unmap_phys(const struct ela_phys_map *map)
{
#if ELA_HAVE_MEMREMAP
	if (map->used_memremap) {
		memunmap((void *)map->base);
		return;
	}
#endif
	iounmap(map->base);
}

/*
 * The transfer loop shared by read and write: window by window, map physical
 * memory and move data through a bounce buffer with memcpy_fromio/_toio
 * (never copy_to/from_user straight against an __iomem pointer).
 */
static long ela_do_phys_io(u64 phys_addr, u64 length, u32 flags,
			   u64 user_buf, bool write)
{
	u8 __user *ubuf = (u8 __user *)(uintptr_t)user_buf;
	u64 phys = phys_addr;
	u64 remaining = length;
	bool uncached = !!(flags & ELA_KMOD_READ_F_UNCACHED);
	u8 *bounce;
	long rc = 0;

	bounce = kmalloc(ELA_BOUNCE_SIZE, GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;

	/*
	 * Default (cached) path: the target is RAM, which is ALREADY mapped in
	 * the kernel's linear map. We must NOT ioremap it — a second mapping
	 * with different cache attributes is an architecturally-illegal alias on
	 * ARMv6+/v7 and takes the machine down (this is exactly how a plain
	 * `memread <ram-addr>` crashed the device). Instead move data through
	 * kmap page by page, reusing the existing coherent mapping (kmap also
	 * handles highmem pages that aren't in the linear map). Non-RAM is
	 * refused up front; device/MMIO must use the --uncached path below.
	 */
	if (!uncached) {
		if (!ela_range_is_ram(phys_addr, length)) {
			kfree(bounce);
			return -ENXIO;
		}
		while (remaining) {
			unsigned long pfn = (unsigned long)(phys >> PAGE_SHIFT);
			size_t off = (size_t)(phys & (PAGE_SIZE - 1));
			size_t chunk = min_t(u64, remaining, (u64)(PAGE_SIZE - off));
			struct page *page = pfn_to_page(pfn);
			void *kva;

			if (chunk > ELA_BOUNCE_SIZE)
				chunk = ELA_BOUNCE_SIZE;

			/* copy_{from,to}_user can fault/sleep, so never straddle a
			 * kmap: stage through the bounce buffer while mapped. */
			if (write) {
				if (copy_from_user(bounce, ubuf, chunk)) {
					rc = -EFAULT;
					break;
				}
				kva = kmap(page);
				memcpy((u8 *)kva + off, bounce, chunk);
				kunmap(page);
			} else {
				kva = kmap(page);
				memcpy(bounce, (u8 *)kva + off, chunk);
				kunmap(page);
				if (copy_to_user(ubuf, bounce, chunk)) {
					rc = -EFAULT;
					break;
				}
			}
			phys += chunk;
			ubuf += chunk;
			remaining -= chunk;
		}
		kfree(bounce);
		return rc;
	}

	/* Uncached device/MMIO path: ioremap + memcpy_*io, window by window. */
	while (remaining) {
		size_t window = min_t(u64, remaining, ELA_MAP_WINDOW);
		struct ela_phys_map map;
		size_t done = 0;

		rc = ela_map_phys(phys, window, &map);
		if (rc)
			break;

		while (done < window) {
			size_t chunk = min_t(size_t, window - done, ELA_BOUNCE_SIZE);

			if (write) {
				if (copy_from_user(bounce, ubuf + done, chunk)) {
					rc = -EFAULT;
					break;
				}
				memcpy_toio(map.va + done, bounce, chunk);
			} else {
				memcpy_fromio(bounce, map.va + done, chunk);
				if (copy_to_user(ubuf + done, bounce, chunk)) {
					rc = -EFAULT;
					break;
				}
			}
			done += chunk;
		}

		ela_unmap_phys(&map);

		if (rc)
			break;

		phys += window;
		ubuf += window;
		remaining -= window;
	}

	kfree(bounce);
	return rc;
}

/* read and write requests share one layout (asserted in the agent's ABI
 * tests), so both ioctls validate through the read struct. */
static long ela_ioctl_phys(unsigned long arg, bool write)
{
	struct ela_kmod_read_phys req;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	if (req.flags & ~ELA_KMOD_READ_F_ALL)
		return -EINVAL;
	if (req.length == 0 || req.length > ELA_KMOD_MAX_READ)
		return -EINVAL;
	if (req.phys_addr + req.length < req.phys_addr) /* wrap */
		return -EINVAL;
	if (!req.buf)
		return -EFAULT;

	return ela_do_phys_io(req.phys_addr, req.length, req.flags, req.buf, write);
}

/*
 * One naturally-aligned device-width MMIO access through an uncached
 * mapping. Distinct from the bulk phys-io path on purpose: device registers
 * with side effects need exactly one access of exactly the right width,
 * which memcpy_fromio does not guarantee. Alignment is required, so an
 * access can never cross the mapped page (a latent bug in chipsec's
 * version, where an 8-byte read at offset 0xFFC runs off its one-page map).
 */
static long ela_ioctl_mmio(unsigned long arg, bool write)
{
	struct ela_kmod_mmio req;
	void __iomem *base;
	void __iomem *va;
	u64 aligned;
	size_t offset;
	long rc = 0;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	if (req.width != 1 && req.width != 2 && req.width != 4 && req.width != 8)
		return -EINVAL;
	if (req.phys_addr & (req.width - 1))
		return -EINVAL;

	aligned = req.phys_addr & ~(u64)(PAGE_SIZE - 1);
	offset = req.phys_addr - aligned;
	if (aligned != (u64)(phys_addr_t)aligned)
		return -ENXIO;

	base = ela_ioremap_uncached((phys_addr_t)aligned, PAGE_SIZE);
	if (!base)
		return -ENXIO;
	va = base + offset;

	if (write) {
		switch (req.width) {
		case 1: iowrite8((u8)req.value, va); break;
		case 2: iowrite16((u16)req.value, va); break;
		case 4: iowrite32((u32)req.value, va); break;
		case 8: writeq(req.value, va); break;
		}
	} else {
		switch (req.width) {
		case 1: req.value = ioread8(va); break;
		case 2: req.value = ioread16(va); break;
		case 4: req.value = ioread32(va); break;
		case 8: req.value = readq(va); break;
		}
	}

	iounmap(base);

	if (!write && copy_to_user((void __user *)arg, &req, sizeof(req)))
		rc = -EFAULT;
	return rc;
}

static long ela_ioctl_pci_cfg(unsigned long arg, bool write)
{
#ifdef CONFIG_PCI
	struct ela_kmod_pci_cfg req;
	struct pci_dev *pdev;
	int rc = 0;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	if (req.width != 1 && req.width != 2 && req.width != 4)
		return -EINVAL;
	if (req.device > 31 || req.function > 7)
		return -EINVAL;
	/* 4096: extended config space; the accessors fail cleanly on buses
	 * that only decode the conventional 256 bytes. */
	if (req.offset >= 4096 || (req.offset & (req.width - 1)))
		return -EINVAL;

	pdev = pci_get_domain_bus_and_slot(req.domain, req.bus,
					   PCI_DEVFN(req.device, req.function));
	if (!pdev)
		return -ENODEV;

	if (write) {
		switch (req.width) {
		case 1: rc = pci_write_config_byte(pdev, req.offset, (u8)req.value); break;
		case 2: rc = pci_write_config_word(pdev, req.offset, (u16)req.value); break;
		case 4: rc = pci_write_config_dword(pdev, req.offset, req.value); break;
		}
	} else {
		u8 v8; u16 v16; u32 v32;

		switch (req.width) {
		case 1: rc = pci_read_config_byte(pdev, req.offset, &v8); req.value = v8; break;
		case 2: rc = pci_read_config_word(pdev, req.offset, &v16); req.value = v16; break;
		case 4: rc = pci_read_config_dword(pdev, req.offset, &v32); req.value = v32; break;
		}
	}
	pci_dev_put(pdev);

	if (rc)
		return -EIO;
	if (!write && copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
#else
	(void)arg;
	(void)write;
	return -EOPNOTSUPP;
#endif
}

static long ela_ioctl_ioport(unsigned long arg, bool write)
{
#ifdef CONFIG_X86
	struct ela_kmod_ioport req;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION || req.port > 0xffff ||
	    (req.width != 1 && req.width != 2 && req.width != 4))
		return -EINVAL;
	if (write && req.width < 4 && req.value >= (1U << (req.width * 8)))
		return -EINVAL;

	if (write) {
		switch (req.width) {
		case 1: outb((u8)req.value, (u16)req.port); break;
		case 2: outw((u16)req.value, (u16)req.port); break;
		case 4: outl(req.value, (u16)req.port); break;
		}
		return 0;
	}

	switch (req.width) {
	case 1: req.value = inb((u16)req.port); break;
	case 2: req.value = inw((u16)req.port); break;
	case 4: req.value = inl((u16)req.port); break;
	}
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
#else
	(void)arg;
	(void)write;
	return -EOPNOTSUPP;
#endif
}

static long ela_ioctl_alloc_phys(struct ela_file_state *state, unsigned long arg)
{
	struct ela_kmod_alloc_phys req;
	struct ela_phys_alloc *alloc;
	unsigned int order;
	unsigned long virt;
	phys_addr_t phys;
	gfp_t gfp = GFP_KERNEL | __GFP_ZERO;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	if (req.length == 0 || req.length > ELA_KMOD_MAX_READ)
		return -EINVAL;

	order = get_order(req.length);

	/* Steer low allocations the way chipsec does: DMA zone below 16 MiB,
	 * DMA32 below 4 GiB, otherwise anywhere — then verify the placement,
	 * since a zone is a hint, not a guarantee. */
#ifdef CONFIG_ZONE_DMA
	if (req.max_phys_addr && req.max_phys_addr <= (16UL << 20))
		gfp |= __GFP_DMA;
	else
#endif
#ifdef CONFIG_ZONE_DMA32
	if (req.max_phys_addr && req.max_phys_addr <= 0xFFFFFFFFULL)
		gfp |= __GFP_DMA32;
#endif

	virt = __get_free_pages(gfp, order);
	if (!virt)
		return -ENOMEM;
	phys = virt_to_phys((void *)virt);
	if (req.max_phys_addr &&
	    (u64)phys + ((u64)PAGE_SIZE << order) - 1 > req.max_phys_addr) {
		free_pages(virt, order);
		return -ENOMEM;
	}

	alloc = kmalloc(sizeof(*alloc), GFP_KERNEL);
	if (!alloc) {
		free_pages(virt, order);
		return -ENOMEM;
	}
	alloc->phys = phys;
	alloc->virt = virt;
	alloc->order = order;

	mutex_lock(&state->lock);
	list_add(&alloc->node, &state->allocations);
	mutex_unlock(&state->lock);

	req.phys_addr = (u64)phys;
	if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
		mutex_lock(&state->lock);
		list_del(&alloc->node);
		mutex_unlock(&state->lock);
		free_pages(virt, order);
		kfree(alloc);
		return -EFAULT;
	}
	return 0;
}

static long ela_ioctl_free_phys(struct ela_file_state *state, unsigned long arg)
{
	struct ela_kmod_free_phys req;
	struct ela_phys_alloc *alloc;
	struct ela_phys_alloc *found = NULL;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;

	mutex_lock(&state->lock);
	list_for_each_entry(alloc, &state->allocations, node) {
		if ((u64)alloc->phys == req.phys_addr) {
			list_del(&alloc->node);
			found = alloc;
			break;
		}
	}
	mutex_unlock(&state->lock);

	if (!found)
		return -ENOENT;
	free_pages(found->virt, found->order);
	kfree(found);
	return 0;
}

static long ela_ioctl_va2pa(unsigned long arg)
{
	struct ela_kmod_va2pa req;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	/* Linear-map addresses only: vmalloc/user pointers have no single
	 * physical address and virt_to_phys on them is undefined. */
	if (!virt_addr_valid((void *)(uintptr_t)req.virt_addr))
		return -EINVAL;

	req.phys_addr = (u64)virt_to_phys((void *)(uintptr_t)req.virt_addr);
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

#ifdef CONFIG_PCI
static long ela_ioctl_orom_get(unsigned long arg)
{
	struct ela_kmod_orom_device req;
	struct pci_dev *pdev = NULL;
	u32 position = 0;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;

	for_each_pci_dev(pdev) {
		void __iomem *rom;
		size_t rom_size = 0;

		rom = pci_map_rom(pdev, &rom_size);
		if (IS_ERR_OR_NULL(rom))
			continue;
		if (!rom_size) {
			pci_unmap_rom(pdev, rom);
			continue;
		}
		if (position++ != req.ordinal) {
			pci_unmap_rom(pdev, rom);
			continue;
		}
		req.domain = (u32)pci_domain_nr(pdev->bus);
		req.bus = pdev->bus->number;
		req.device = PCI_SLOT(pdev->devfn);
		req.function = PCI_FUNC(pdev->devfn);
		req.vendor_id = pdev->vendor;
		req.device_id = pdev->device;
		req.class_code = pdev->class;
		req.pad = 0;
		req.size = rom_size;
		pci_unmap_rom(pdev, rom);
		pci_dev_put(pdev);
		if (copy_to_user((void __user *)arg, &req, sizeof(req)))
			return -EFAULT;
		return 0;
	}
	return -ENOENT;
}

static long ela_ioctl_orom_read(unsigned long arg)
{
	struct ela_kmod_orom_read req;
	struct pci_dev *pdev;
	void __iomem *rom;
	void *buf;
	size_t rom_size = 0;
	long rc = 0;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION || req.pad ||
	    req.domain > INT_MAX || req.bus > U8_MAX ||
	    req.device > 31 || req.function > 7 || !req.buf || !req.length ||
	    req.length > ELA_KMOD_OROM_MAX_READ ||
	    req.offset + req.length < req.offset)
		return -EINVAL;

	pdev = pci_get_domain_bus_and_slot((int)req.domain, (u8)req.bus,
					   PCI_DEVFN(req.device, req.function));
	if (!pdev)
		return -ENODEV;
	rom = pci_map_rom(pdev, &rom_size);
	if (IS_ERR_OR_NULL(rom)) {
		rc = IS_ERR(rom) ? PTR_ERR(rom) : -ENODEV;
		goto out_put;
	}
	if (req.offset > rom_size || req.length > rom_size - req.offset) {
		rc = -EINVAL;
		goto out_unmap;
	}
	buf = kvmalloc((size_t)req.length, GFP_KERNEL);
	if (!buf) {
		rc = -ENOMEM;
		goto out_unmap;
	}
	memcpy_fromio(buf, rom + req.offset, (size_t)req.length);
	if (copy_to_user((void __user *)(uintptr_t)req.buf, buf,
			 (size_t)req.length))
		rc = -EFAULT;
	kvfree(buf);
out_unmap:
	pci_unmap_rom(pdev, rom);
out_put:
	pci_dev_put(pdev);
	return rc;
}
#else
static long ela_ioctl_orom_get(unsigned long arg)
{
	(void)arg;
	return -EOPNOTSUPP;
}

static long ela_ioctl_orom_read(unsigned long arg)
{
	(void)arg;
	return -EOPNOTSUPP;
}
#endif

static void ela_copy_fixed_name(char *dst, size_t dst_len, const char *src)
{
	size_t len;

	if (!dst_len)
		return;
	len = strnlen(src, dst_len - 1);
	memcpy(dst, src, len);
	dst[len] = '\0';
}

#ifdef ELA_HAVE_USB
struct ela_usb_find_ctx {
	u32 busnum;
	u32 devnum;
	struct usb_device *found;
};

static int ela_usb_find_cb(struct usb_device *udev, void *data)
{
	struct ela_usb_find_ctx *ctx = data;

	if (udev->bus->busnum != ctx->busnum || udev->devnum != ctx->devnum)
		return 0;
	ctx->found = usb_get_dev(udev);
	return 1;
}

static struct usb_device *ela_usb_find(u32 busnum, u32 devnum)
{
	struct ela_usb_find_ctx ctx = {
		.busnum = busnum,
		.devnum = devnum,
	};

	usb_for_each_dev(&ctx, ela_usb_find_cb);
	return ctx.found;
}

struct ela_usb_get_ctx {
	u32 wanted;
	u32 position;
	bool found;
	struct ela_kmod_usb_device *record;
};

static int ela_usb_get_cb(struct usb_device *udev, void *data)
{
	struct ela_usb_get_ctx *ctx = data;
	struct ela_kmod_usb_device *req = ctx->record;

	if (ctx->position++ != ctx->wanted)
		return 0;
	req->busnum = udev->bus->busnum;
	req->devnum = udev->devnum;
	req->parent_busnum = udev->parent ? udev->parent->bus->busnum : 0;
	req->parent_devnum = udev->parent ? udev->parent->devnum : 0;
	req->portnum = udev->portnum;
	req->speed = udev->speed;
	req->vendor_id = le16_to_cpu(udev->descriptor.idVendor);
	req->product_id = le16_to_cpu(udev->descriptor.idProduct);
	req->device_class = udev->descriptor.bDeviceClass;
	req->device_subclass = udev->descriptor.bDeviceSubClass;
	req->device_protocol = udev->descriptor.bDeviceProtocol;
	req->num_configurations = udev->descriptor.bNumConfigurations;
	req->maxchild = udev->maxchild;
	req->pad = 0;
	memset(req->manufacturer, 0, sizeof(req->manufacturer));
	memset(req->product, 0, sizeof(req->product));
	memset(req->serial, 0, sizeof(req->serial));
	if (udev->manufacturer)
		ela_copy_fixed_name(req->manufacturer, sizeof(req->manufacturer),
				    udev->manufacturer);
	if (udev->product)
		ela_copy_fixed_name(req->product, sizeof(req->product),
				    udev->product);
	if (udev->serial)
		ela_copy_fixed_name(req->serial, sizeof(req->serial), udev->serial);
	ctx->found = true;
	return 1;
}

static long ela_ioctl_usb_get(unsigned long arg)
{
	struct ela_kmod_usb_device req;
	struct ela_usb_get_ctx ctx;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	memset(&ctx, 0, sizeof(ctx));
	ctx.wanted = req.ordinal;
	ctx.record = &req;
	usb_for_each_dev(&ctx, ela_usb_get_cb);
	if (!ctx.found)
		return -ENOENT;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

static long ela_ioctl_usb_reset(unsigned long arg)
{
	struct ela_kmod_usb_reset req;
	struct usb_device *udev;
	int rc;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION || req.pad ||
	    !req.busnum || !req.devnum)
		return -EINVAL;
	udev = ela_usb_find(req.busnum, req.devnum);
	if (!udev)
		return -ENODEV;
	rc = usb_lock_device_for_reset(udev, NULL);
	if (rc >= 0) {
		rc = usb_reset_device(udev);
		usb_unlock_device(udev);
	}
	usb_put_dev(udev);
	return rc;
}

struct ela_usb_port_ctx {
	u32 wanted;
	u32 position;
	bool found;
	struct ela_kmod_usb_port *record;
};

static int ela_usb_port_get_status(struct usb_device *hub, u32 portnum,
				   u32 *status, u32 *change)
{
	struct usb_port_status raw;
	int rc;

	usb_lock_device(hub);
	rc = usb_control_msg(hub, usb_rcvctrlpipe(hub, 0), USB_REQ_GET_STATUS,
			     USB_DIR_IN | USB_RT_PORT, 0, portnum, &raw,
			     sizeof(raw), 1000);
	usb_unlock_device(hub);
	if (rc < 0)
		return rc;
	if (rc != sizeof(raw))
		return -EIO;
	*status = le16_to_cpu(raw.wPortStatus);
	*change = le16_to_cpu(raw.wPortChange);
	return 0;
}

static int ela_usb_port_get_cb(struct usb_device *hub, void *data)
{
	struct ela_usb_port_ctx *ctx = data;
	u32 portnum;

	for (portnum = 1; portnum <= hub->maxchild; portnum++) {
		struct usb_device *child;
		int rc;

		if (ctx->position++ != ctx->wanted)
			continue;
		ctx->record->hub_busnum = hub->bus->busnum;
		ctx->record->hub_devnum = hub->devnum;
		ctx->record->portnum = portnum;
		ctx->record->child_busnum = 0;
		ctx->record->child_devnum = 0;
		ctx->record->hub_speed = hub->speed;
		usb_lock_device(hub);
		child = usb_hub_find_child(hub, portnum);
		if (child)
			usb_get_dev(child);
		usb_unlock_device(hub);
		if (child) {
			ctx->record->child_busnum = child->bus->busnum;
			ctx->record->child_devnum = child->devnum;
			usb_put_dev(child);
		}
		rc = ela_usb_port_get_status(hub, portnum,
					     &ctx->record->status,
					     &ctx->record->change);
		if (rc)
			return rc;
		ctx->found = true;
		return 1;
	}
	return 0;
}

static long ela_ioctl_usb_port_get(unsigned long arg)
{
	struct ela_kmod_usb_port req;
	struct ela_usb_port_ctx ctx;
	int rc;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	memset(&ctx, 0, sizeof(ctx));
	ctx.wanted = req.ordinal;
	ctx.record = &req;
	rc = usb_for_each_dev(&ctx, ela_usb_port_get_cb);
	if (rc < 0)
		return rc;
	if (!ctx.found)
		return -ENOENT;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

static long ela_ioctl_usb_port_action(unsigned long arg)
{
	struct ela_kmod_usb_port_action req;
	struct usb_device *hub;
	struct usb_device *child;
	int rc;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION || req.pad ||
	    !req.hub_busnum || !req.hub_devnum || !req.portnum ||
	    (req.action != ELA_USB_PORT_ACTION_RESET &&
	     req.action != ELA_USB_PORT_ACTION_POWER_CYCLE))
		return -EINVAL;
	hub = ela_usb_find(req.hub_busnum, req.hub_devnum);
	if (!hub)
		return -ENODEV;
	if (req.portnum > hub->maxchild) {
		rc = -EINVAL;
		goto out_hub;
	}
	if (req.action == ELA_USB_PORT_ACTION_RESET) {
		usb_lock_device(hub);
		child = usb_hub_find_child(hub, req.portnum);
		if (child)
			usb_get_dev(child);
		usb_unlock_device(hub);
		if (!child) {
			rc = -ENODEV;
			goto out_hub;
		}
		rc = usb_lock_device_for_reset(child, NULL);
		if (rc >= 0) {
			rc = usb_reset_device(child);
			usb_unlock_device(child);
		}
		usb_put_dev(child);
		goto out_hub;
	}

	usb_lock_device(hub);
	rc = usb_control_msg(hub, usb_sndctrlpipe(hub, 0),
			     USB_REQ_CLEAR_FEATURE, USB_RT_PORT,
			     USB_PORT_FEAT_POWER, req.portnum, NULL, 0, 1000);
	if (rc >= 0) {
		msleep(250);
		rc = usb_control_msg(hub, usb_sndctrlpipe(hub, 0),
				     USB_REQ_SET_FEATURE, USB_RT_PORT,
				     USB_PORT_FEAT_POWER, req.portnum,
				     NULL, 0, 1000);
	}
	usb_unlock_device(hub);
out_hub:
	usb_put_dev(hub);
	return rc;
}

static long ela_ioctl_usb_descriptors(unsigned long arg)
{
	struct ela_kmod_usb_descriptors req;
	struct usb_device *udev;
	u8 *buf;
	size_t total;
	u32 i;
	long rc = 0;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION || req.pad || !req.buf ||
	    !req.length || req.length > ELA_KMOD_USB_DESC_MAX ||
	    !req.busnum || !req.devnum)
		return -EINVAL;
	udev = ela_usb_find(req.busnum, req.devnum);
	if (!udev)
		return -ENODEV;
	usb_lock_device(udev);
	total = sizeof(udev->descriptor);
	for (i = 0; i < udev->descriptor.bNumConfigurations; i++) {
		size_t config_len;

		if (!udev->config || !udev->rawdescriptors ||
		    !udev->rawdescriptors[i]) {
			rc = -ENODATA;
			goto out_unlock;
		}
		config_len = le16_to_cpu(udev->config[i].desc.wTotalLength);
		if (config_len > ELA_KMOD_USB_DESC_MAX - total) {
			rc = -EOVERFLOW;
			goto out_unlock;
		}
		total += config_len;
	}
	req.actual_length = total;
	if (total > req.length) {
		rc = -ENOSPC;
		goto out_unlock_copy_req;
	}
	buf = kvmalloc(total, GFP_KERNEL);
	if (!buf) {
		rc = -ENOMEM;
		goto out_unlock;
	}
	memcpy(buf, &udev->descriptor, sizeof(udev->descriptor));
	total = sizeof(udev->descriptor);
	for (i = 0; i < udev->descriptor.bNumConfigurations; i++) {
		size_t config_len = le16_to_cpu(udev->config[i].desc.wTotalLength);

		memcpy(buf + total, udev->rawdescriptors[i], config_len);
		total += config_len;
	}
	usb_unlock_device(udev);
	if (copy_to_user((void __user *)(uintptr_t)req.buf, buf, total))
		rc = -EFAULT;
	kvfree(buf);
out_copy_req:
	if (copy_to_user((void __user *)arg, &req, sizeof(req)) && !rc)
		rc = -EFAULT;
out_put:
	usb_put_dev(udev);
	return rc;
out_unlock_copy_req:
	usb_unlock_device(udev);
	goto out_copy_req;
out_unlock:
	usb_unlock_device(udev);
	goto out_put;
}
#else
static long ela_ioctl_usb_get(unsigned long arg) { (void)arg; return -EOPNOTSUPP; }
static long ela_ioctl_usb_reset(unsigned long arg) { (void)arg; return -EOPNOTSUPP; }
static long ela_ioctl_usb_port_get(unsigned long arg) { (void)arg; return -EOPNOTSUPP; }
static long ela_ioctl_usb_port_action(unsigned long arg) { (void)arg; return -EOPNOTSUPP; }
static long ela_ioctl_usb_descriptors(unsigned long arg) { (void)arg; return -EOPNOTSUPP; }
#endif

#if IS_BUILTIN(CONFIG_SPI)
struct ela_spi_find_ctx {
	u32 wanted;
	u32 position;
	bool found;
	struct ela_kmod_spi_device *record;
};

static int ela_spi_find_device(struct device *dev, void *data)
{
	struct ela_spi_find_ctx *ctx = data;
	struct spi_device *spi;

	if (ctx->position++ != ctx->wanted)
		return 0;
	spi = to_spi_device(dev);
	ela_copy_fixed_name(ctx->record->device_name, ELA_KMOD_SPI_NAME_LEN,
		dev_name(dev));
	ela_copy_fixed_name(ctx->record->modalias, ELA_KMOD_SPI_NAME_LEN,
		spi->modalias);
	if (dev->driver)
		ela_copy_fixed_name(ctx->record->driver,
			ELA_KMOD_SPI_DRIVER_LEN, dev->driver->name);
	ctx->record->mode = spi->mode;
	ctx->record->max_speed_hz = spi->max_speed_hz;
	ctx->record->bits_per_word = spi->bits_per_word;
	ctx->found = true;
	return 1;
}

static long ela_ioctl_spi_get(unsigned long arg)
{
	struct ela_kmod_spi_device req;
	struct ela_spi_find_ctx ctx;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;

	memset(req.device_name, 0, sizeof(req.device_name));
	memset(req.modalias, 0, sizeof(req.modalias));
	memset(req.driver, 0, sizeof(req.driver));
	req.mode = 0;
	req.max_speed_hz = 0;
	req.bits_per_word = 0;
	req.pad = 0;
	memset(&ctx, 0, sizeof(ctx));
	ctx.wanted = req.ordinal;
	ctx.record = &req;
	bus_for_each_dev(&spi_bus_type, NULL, &ctx, ela_spi_find_device);
	if (!ctx.found)
		return -ENOENT;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}
#else
static long ela_ioctl_spi_get(unsigned long arg)
{
	(void)arg;
	return -EOPNOTSUPP;
}
#endif

#if defined(ELA_HAVE_MTD) && IS_BUILTIN(CONFIG_SPI)
static struct spi_device *ela_mtd_spi_parent(struct mtd_info *mtd)
{
	struct device *dev = mtd->dev.parent;

	while (dev) {
		if (dev->bus == &spi_bus_type)
			return to_spi_device(dev);
		dev = dev->parent;
	}
	return NULL;
}

struct ela_spi_mtd_find_ctx {
	u32 wanted;
	u32 position;
	bool found;
	struct ela_kmod_spi_mtd *record;
};

static int ela_spi_find_mtd_child(struct device *dev, void *data)
{
	struct ela_spi_mtd_find_ctx *ctx = data;
	struct mtd_info *mtd;
	struct spi_device *spi;
	const char *name = dev_name(dev);
	char *end;
	long index;

	if (strncmp(name, "mtd", 3) || name[3] < '0' || name[3] > '9')
		return 0;
	index = simple_strtol(name + 3, &end, 10);
	if (*end || index < 0)
		return 0;
	mtd = get_mtd_device(NULL, (int)index);
	if (IS_ERR(mtd))
		return 0;
	if (&mtd->dev != dev || !(spi = ela_mtd_spi_parent(mtd))) {
		put_mtd_device(mtd);
		return 0;
	}
	if (ctx->position++ != ctx->wanted) {
		put_mtd_device(mtd);
		return 0;
	}

	ctx->record->mtd_index = (u32)index;
	ctx->record->size = mtd->size;
	ctx->record->erasesize = mtd->erasesize;
	ctx->record->writesize = mtd->writesize;
	ela_copy_fixed_name(ctx->record->spi_name, ELA_KMOD_SPI_NAME_LEN,
		dev_name(&spi->dev));
	ela_copy_fixed_name(ctx->record->mtd_name, ELA_KMOD_MTD_NAME_LEN,
		mtd->name);
	ctx->found = true;
	put_mtd_device(mtd);
	return 1;
}

static int ela_spi_find_mtd_under_device(struct device *dev, void *data)
{
	struct ela_spi_mtd_find_ctx *ctx = data;

	device_for_each_child(dev, ctx, ela_spi_find_mtd_child);
	return ctx->found ? 1 : 0;
}

static long ela_ioctl_spi_mtd_get(unsigned long arg)
{
	struct ela_kmod_spi_mtd req;
	struct ela_spi_mtd_find_ctx ctx;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;

	memset(req.spi_name, 0, sizeof(req.spi_name));
	memset(req.mtd_name, 0, sizeof(req.mtd_name));
	req.mtd_index = 0;
	req.writesize = 0;
	req.erasesize = 0;
	req.pad = 0;
	req.size = 0;
	memset(&ctx, 0, sizeof(ctx));
	ctx.wanted = req.ordinal;
	ctx.record = &req;
	bus_for_each_dev(&spi_bus_type, NULL, &ctx,
			 ela_spi_find_mtd_under_device);
	if (!ctx.found)
		return -ENOENT;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

static long ela_ioctl_spi_mtd_read(unsigned long arg)
{
	struct ela_kmod_spi_mtd_read req;
	struct mtd_info *mtd;
	u8 *buf;
	size_t retlen = 0;
	int rc;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	if (!req.buf || !req.length || req.length > ELA_KMOD_SPI_MAX_READ ||
	    req.offset + req.length < req.offset)
		return -EINVAL;

	mtd = get_mtd_device(NULL, (int)req.mtd_index);
	if (IS_ERR(mtd))
		return PTR_ERR(mtd);
	if (!ela_mtd_spi_parent(mtd)) {
		rc = -ENODEV;
		goto out_put;
	}
	if (req.offset > mtd->size || req.length > mtd->size - req.offset) {
		rc = -EINVAL;
		goto out_put;
	}
	buf = kmalloc((size_t)req.length, GFP_KERNEL);
	if (!buf) {
		rc = -ENOMEM;
		goto out_put;
	}
	rc = mtd_read(mtd, (loff_t)req.offset, (size_t)req.length,
		      &retlen, buf);
	if (mtd_is_bitflip(rc))
		rc = 0;
	if (!rc && retlen != (size_t)req.length)
		rc = -EIO;
	if (!rc && copy_to_user((void __user *)(uintptr_t)req.buf,
				buf, (size_t)req.length))
		rc = -EFAULT;
	kfree(buf);
out_put:
	put_mtd_device(mtd);
	return rc;
}
#else
static long ela_ioctl_spi_mtd_get(unsigned long arg)
{
	(void)arg;
	return -EOPNOTSUPP;
}

static long ela_ioctl_spi_mtd_read(unsigned long arg)
{
	(void)arg;
	return -EOPNOTSUPP;
}
#endif

#ifdef ELA_HAVE_MTD
static long ela_ioctl_nand_mtd_get(unsigned long arg)
{
	struct ela_kmod_nand_mtd req;
	struct ela_nand_entry *entry;
	struct mtd_info *mtd;
	u32 position = 0;
	int mtd_index = -1;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;

	mutex_lock(&ela_nand_lock);
	list_for_each_entry(entry, &ela_nand_entries, node) {
		if (position++ == req.ordinal) {
			mtd_index = entry->mtd_index;
			break;
		}
	}
	mutex_unlock(&ela_nand_lock);
	if (mtd_index < 0)
		return -ENOENT;

	mtd = get_mtd_device(NULL, mtd_index);
	if (IS_ERR(mtd))
		return PTR_ERR(mtd);
	if (!ela_mtd_is_nand(mtd)) {
		put_mtd_device(mtd);
		return -ENODEV;
	}
	req.mtd_index = (u32)mtd_index;
	req.type = mtd->type;
	req.writesize = mtd->writesize;
	req.erasesize = mtd->erasesize;
	req.oobsize = mtd->oobsize;
	req.ecc_strength = mtd->ecc_strength;
	req.size = mtd->size;
	memset(req.mtd_name, 0, sizeof(req.mtd_name));
	ela_copy_fixed_name(req.mtd_name, ELA_KMOD_MTD_NAME_LEN, mtd->name);
	put_mtd_device(mtd);

	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

static long ela_ioctl_nand_mtd_read(unsigned long arg)
{
	struct ela_kmod_nand_mtd_read req;
	struct mtd_info *mtd;
	u8 *buf;
	u64 position;
	u64 remaining;
	size_t output_offset = 0;
	int rc = 0;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	if (!req.buf || !req.length || req.length > ELA_KMOD_NAND_MAX_READ ||
	    req.offset + req.length < req.offset)
		return -EINVAL;

	mtd = get_mtd_device(NULL, (int)req.mtd_index);
	if (IS_ERR(mtd))
		return PTR_ERR(mtd);
	if (!ela_mtd_is_nand(mtd)) {
		rc = -ENODEV;
		goto out_put;
	}
	if (!mtd->erasesize || req.offset > mtd->size ||
	    req.length > mtd->size - req.offset) {
		rc = -EINVAL;
		goto out_put;
	}
	buf = kmalloc((size_t)req.length, GFP_KERNEL);
	if (!buf) {
		rc = -ENOMEM;
		goto out_put;
	}

	req.bad_blocks = 0;
	req.pad = 0;
	position = req.offset;
	remaining = req.length;
	while (remaining) {
		u64 block_start = position - (position % mtd->erasesize);
		u64 block_remaining = mtd->erasesize - (position - block_start);
		size_t chunk = (size_t)min_t(u64, remaining, block_remaining);
		size_t retlen = 0;
		int bad = mtd_block_isbad(mtd, (loff_t)block_start);

		if (bad < 0) {
			rc = bad;
			break;
		}
		if (bad) {
			memset(buf + output_offset, 0xff, chunk);
			req.bad_blocks++;
		} else {
			rc = mtd_read(mtd, (loff_t)position, chunk, &retlen,
				      buf + output_offset);
			if (mtd_is_bitflip(rc))
				rc = 0;
			if (rc || retlen != chunk) {
				if (!rc)
					rc = -EIO;
				break;
			}
		}
		position += chunk;
		remaining -= chunk;
		output_offset += chunk;
	}
	if (!rc && copy_to_user((void __user *)(uintptr_t)req.buf,
				buf, (size_t)req.length))
		rc = -EFAULT;
	if (!rc && copy_to_user((void __user *)arg, &req, sizeof(req)))
		rc = -EFAULT;
	kfree(buf);
out_put:
	put_mtd_device(mtd);
	return rc;
}
#else
static long ela_ioctl_nand_mtd_get(unsigned long arg)
{
	(void)arg;
	return -EOPNOTSUPP;
}

static long ela_ioctl_nand_mtd_read(unsigned long arg)
{
	(void)arg;
	return -EOPNOTSUPP;
}
#endif

/* ---- WLAN firmware-command injection shim ------------------------------- *
 *
 * A kprobe on the driver's firmware command-send function captures the live
 * driver-private context from the driver's own traffic and resolves the send
 * address; ELA_IOC_WLAN_INJECT then calls that function with an
 * attacker-supplied command buffer. A second kprobe on the driver's
 * firmware-restart entry counts crashes -- the fuzzer's liveness oracle.
 * See kmod/ela_ioctl.h for the ABI and the authorized-use warning.
 */
#if IS_ENABLED(CONFIG_KPROBES) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)

#define ELA_WLAN_SKB_HEADROOM 64	/* room for the WMI/HTC headers the
					 * driver push()es onto the skb */

typedef int (*ela_wmi_skb_send_t)(void *ctx, struct sk_buff *skb, u32 cmd_id);

/* WMI-over-skb drivers (ath10k, ath11k) all take (ctx, skb, cmd_id): build a
 * skb with headroom, copy the fuzzed body in, and call the captured send. */
static int ela_wlan_inject_wmi_skb(void *ctx, unsigned long ctx2, void *send_fn,
				   u32 cmd_id, const void *data, u32 len)
{
	struct sk_buff *skb;
	u32 round = round_up(len, 4);
	int ret;

	(void)ctx2;

	skb = __dev_alloc_skb(ELA_WLAN_SKB_HEADROOM + round, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, ELA_WLAN_SKB_HEADROOM);
	skb_put(skb, round);
	memset(skb->data, 0, round);
	if (len)
		memcpy(skb->data, data, len);
	ret = ((ela_wmi_skb_send_t)send_fn)(ctx, skb, cmd_id);
	if (ret)
		kfree_skb(skb);		/* not queued to hardware: reclaim */
	return ret;
}

/* mt76: mt76_mcu_send_and_get_msg(dev, cmd, data, len, wait_resp, ret_skb).
 * It allocates the skb and prepends the MCU txd itself, so we hand it the raw
 * command body. wait_resp=false so it does not block waiting for a response. */
typedef int (*ela_mt76_send_t)(void *dev, int cmd, const void *data, int len,
			       bool wait_resp, void *ret_skb);
static int ela_wlan_inject_mt76(void *ctx, unsigned long ctx2, void *send_fn,
				u32 cmd_id, const void *data, u32 len)
{
	(void)ctx2;
	return ((ela_mt76_send_t)send_fn)(ctx, (int)cmd_id, data, (int)len,
					  false, NULL);
}

/* brcmfmac: brcmf_fil_cmd_data_set(ifp, cmd, data, len) sends a BCDC firmware
 * ioctl (set path). It copies the buffer and takes its own proto lock. */
typedef int (*ela_brcmf_send_t)(void *ifp, u32 cmd, void *data, u32 len);
static int ela_wlan_inject_brcmfmac(void *ctx, unsigned long ctx2,
				    void *send_fn, u32 cmd_id, const void *data,
				    u32 len)
{
	(void)ctx2;
	return ((ela_brcmf_send_t)send_fn)(ctx, cmd_id, (void *)data, len);
}

/* ---- ethernet firmware-mailbox / admin-queue inject shims ----------------- */

/* Intel i40e/ice Admin Queue: a fixed 32-byte descriptor (opcode + flags +
 * datalen + params) plus an optional external buffer. The AQ send copies the
 * buffer into the AQ DMA area and writes the completion back into the desc, so
 * both must be writable. data = <32B desc><optional buffer>. */
#define ELA_AQ_DESC_LEN 32
typedef int (*ela_i40e_asq_t)(void *hw, void *desc, void *buff, u16 buff_size,
			      void *cmd_details);
static int ela_eth_inject_i40e(void *ctx, unsigned long ctx2, void *send_fn,
			       u32 cmd_id, const void *data, u32 len)
{
	u8 desc[ELA_AQ_DESC_LEN];
	const u8 *buff = NULL;
	u16 buff_size = 0;

	(void)ctx2;
	(void)cmd_id;
	memset(desc, 0, sizeof(desc));
	memcpy(desc, data, len < ELA_AQ_DESC_LEN ? len : ELA_AQ_DESC_LEN);
	if (len > ELA_AQ_DESC_LEN) {
		buff = (const u8 *)data + ELA_AQ_DESC_LEN;
		buff_size = (u16)(len - ELA_AQ_DESC_LEN);
	}
	return ((ela_i40e_asq_t)send_fn)(ctx, desc, (void *)buff, buff_size,
					 NULL);
}

typedef int (*ela_ice_sq_t)(void *hw, void *cq, void *desc, void *buf,
			    u16 buf_size, void *cd);
static int ela_eth_inject_ice(void *ctx, unsigned long ctx2, void *send_fn,
			      u32 cmd_id, const void *data, u32 len)
{
	u8 desc[ELA_AQ_DESC_LEN];
	const u8 *buf = NULL;
	u16 buf_size = 0;

	(void)cmd_id;
	memset(desc, 0, sizeof(desc));
	memcpy(desc, data, len < ELA_AQ_DESC_LEN ? len : ELA_AQ_DESC_LEN);
	if (len > ELA_AQ_DESC_LEN) {
		buf = (const u8 *)data + ELA_AQ_DESC_LEN;
		buf_size = (u16)(len - ELA_AQ_DESC_LEN);
	}
	/* ctx2 = the captured control queue (ice_ctl_q_info *). */
	return ((ela_ice_sq_t)send_fn)(ctx, (void *)ctx2, desc, (void *)buf,
				       buf_size, NULL);
}

/* Chelsio cxgb4 FW_CMD mailbox: t4_wr_mbox_meat_timeout(adap, mbox, cmd, size,
 * rpl, sleep_ok, timeout). Command is size bytes (multiple of 8, <= 64). */
typedef int (*ela_cxgb4_mbox_t)(void *adap, int mbox, const void *cmd, int size,
				void *rpl, bool sleep_ok, int timeout);
static int ela_eth_inject_cxgb4(void *ctx, unsigned long ctx2, void *send_fn,
				u32 cmd_id, const void *data, u32 len)
{
	u8 cmd[64];
	int size = (int)len;

	(void)cmd_id;
	if (size > (int)sizeof(cmd))
		size = sizeof(cmd);
	size &= ~7;			/* FW_CMD size must be 8-byte aligned */
	if (size == 0)
		return -EINVAL;
	memcpy(cmd, data, (size_t)size);
	/* ctx2 = the captured mailbox number; rpl=NULL: fire and forget. */
	return ((ela_cxgb4_mbox_t)send_fn)(ctx, (int)ctx2, cmd, size, NULL,
					   false, 10000);
}

/* Mellanox mlx5 cmdif: mlx5_cmd_exec(dev, in, in_size, out, out_size). The
 * command layout is big-endian; the opcode is the first 16 bits of `in`. */
typedef int (*ela_mlx5_exec_t)(void *dev, void *in, int in_size, void *out,
			       int out_size);
static int ela_eth_inject_mlx5(void *ctx, unsigned long ctx2, void *send_fn,
			       u32 cmd_id, const void *data, u32 len)
{
	void *out;
	int ret;

	(void)ctx2;
	(void)cmd_id;
	out = kzalloc(256, GFP_KERNEL);
	if (!out)
		return -ENOMEM;
	ret = ((ela_mlx5_exec_t)send_fn)(ctx, (void *)data, (int)len, out, 256);
	kfree(out);
	return ret;
}

/* Broadcom bnxt HWRM: bnxt_hwrm_do_send_msg(bp, msg, msg_len, timeout, silent).
 * NOTE: this static symbol exists on pre-5.12 kernels; newer kernels refactored
 * HWRM to __hwrm_send(bp, ctx) where the message rides a DMA buffer rather than
 * an argument, so attach fails there (kprobe symbol not found) -- documented. */
typedef int (*ela_bnxt_hwrm_t)(void *bp, void *msg, u32 msg_len, int timeout,
			       bool silent);
static int ela_eth_inject_bnxt(void *ctx, unsigned long ctx2, void *send_fn,
			       u32 cmd_id, const void *data, u32 len)
{
	(void)ctx2;
	(void)cmd_id;
	return ((ela_bnxt_hwrm_t)send_fn)(ctx, (void *)data, len, 500, false);
}

#define ELA_WLAN_MAX_RESTART_SYMS 5

struct ela_wlan_driver_desc {
	u32 id;
	const char *name;
	const char *send_symbol;	/* firmware command-send function */
	/* candidate firmware-restart/crash entries; the first that resolves is
	 * hooked for the liveness oracle. Some drivers name it per-chip. */
	const char *restart_symbols[ELA_WLAN_MAX_RESTART_SYMS];
	int ctx_arg;			/* send arg index holding the driver ctx */
	int cmd_arg;			/* send arg index holding the command id */
	int ctx2_arg;			/* second ctx arg (-1 if unused): ice cq,
					 * cxgb4 mailbox number */
	int (*inject)(void *ctx, unsigned long ctx2, void *send_fn, u32 cmd_id,
		      const void *data, u32 len);
};

static const struct ela_wlan_driver_desc ela_wlan_drivers[] = {
	{
		.id = ELA_WLAN_DRV_ATH10K,
		.name = "ath10k",
		.send_symbol = "ath10k_wmi_cmd_send",
		.restart_symbols = { "ath10k_core_restart" },
		.ctx_arg = 0, .cmd_arg = 2, .ctx2_arg = -1,
		.inject = ela_wlan_inject_wmi_skb,
	},
	{
		.id = ELA_WLAN_DRV_ATH11K,
		.name = "ath11k",
		.send_symbol = "ath11k_wmi_cmd_send",
		.restart_symbols = { "ath11k_core_restart" },
		.ctx_arg = 0, .cmd_arg = 2, .ctx2_arg = -1,
		.inject = ela_wlan_inject_wmi_skb,
	},
	{
		.id = ELA_WLAN_DRV_ATH12K,
		.name = "ath12k",
		.send_symbol = "ath12k_wmi_cmd_send",
		.restart_symbols = { "ath12k_core_restart" },
		.ctx_arg = 0, .cmd_arg = 2, .ctx2_arg = -1,
		.inject = ela_wlan_inject_wmi_skb,
	},
	{
		.id = ELA_WLAN_DRV_MT76,
		.name = "mt76",
		.send_symbol = "mt76_mcu_send_and_get_msg",
		/* per-chip crash workers; whichever chip is bound resolves */
		.restart_symbols = {
			"mt7921_mac_reset_work", "mt7915_mac_reset_work",
			"mt7996_mac_reset_work", "mt7615_mac_reset_work",
		},
		.ctx_arg = 0, .cmd_arg = 1, .ctx2_arg = -1,
		.inject = ela_wlan_inject_mt76,
	},
	{
		.id = ELA_WLAN_DRV_BRCMFMAC,
		.name = "brcmfmac",
		.send_symbol = "brcmf_fil_cmd_data_set",
		.restart_symbols = { "brcmf_fw_crashed" },
		.ctx_arg = 0, .cmd_arg = 1, .ctx2_arg = -1,
		.inject = ela_wlan_inject_brcmfmac,
	},
	/* ---- ethernet firmware-command drivers ---- */
	{
		.id = ELA_ETH_DRV_BNXT,
		.name = "bnxt",
		.send_symbol = "bnxt_hwrm_do_send_msg",	/* pre-5.12 symbol */
		.restart_symbols = {
			"bnxt_fw_reset", "bnxt_fw_exception", "bnxt_reset_task",
		},
		.ctx_arg = 0, .cmd_arg = 0, .ctx2_arg = -1,
		.inject = ela_eth_inject_bnxt,
	},
	{
		.id = ELA_ETH_DRV_I40E,
		.name = "i40e",
		.send_symbol = "i40e_asq_send_command",
		.restart_symbols = { "i40e_reset_and_rebuild", "i40e_do_reset" },
		.ctx_arg = 0, .cmd_arg = 0, .ctx2_arg = -1,
		.inject = ela_eth_inject_i40e,
	},
	{
		.id = ELA_ETH_DRV_ICE,
		.name = "ice",
		.send_symbol = "ice_sq_send_cmd",
		.restart_symbols = { "ice_rebuild", "ice_do_reset" },
		.ctx_arg = 0, .cmd_arg = 0, .ctx2_arg = 1,	/* ctx2 = cq */
		.inject = ela_eth_inject_ice,
	},
	{
		.id = ELA_ETH_DRV_CXGB4,
		.name = "cxgb4",
		.send_symbol = "t4_wr_mbox_meat_timeout",
		.restart_symbols = { "t4_fatal_err" },
		.ctx_arg = 0, .cmd_arg = 0, .ctx2_arg = 1,	/* ctx2 = mbox */
		.inject = ela_eth_inject_cxgb4,
	},
	{
		.id = ELA_ETH_DRV_MLX5,
		.name = "mlx5",
		.send_symbol = "mlx5_cmd_exec",
		.restart_symbols = { "mlx5_enter_error_state",
				     "mlx5_recover_device" },
		.ctx_arg = 0, .cmd_arg = 0, .ctx2_arg = -1,
		.inject = ela_eth_inject_mlx5,
	},
};

static DEFINE_MUTEX(ela_wlan_mutex);	/* serialises attach/detach */
static DEFINE_SPINLOCK(ela_wlan_lock);	/* guards the fields below */
static struct {
	const struct ela_wlan_driver_desc *desc;
	void *ctx;
	unsigned long ctx2;		/* second captured arg (ice cq / cxgb4 mbox) */
	void *send_fn;
	u32 captured;
	u32 last_cmd_id;
	u64 send_count;
	u64 inject_count;
	u64 restart_count;
} ela_wlan;
static struct kprobe ela_wlan_kp_send;
static struct kprobe ela_wlan_kp_restart;
static bool ela_wlan_armed;
static bool ela_wlan_restart_armed;	/* restart kprobe is best-effort */

static int ela_wlan_send_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long flags;

	spin_lock_irqsave(&ela_wlan_lock, flags);
	if (ela_wlan.desc) {
		ela_wlan.ctx = (void *)regs_get_kernel_argument(regs,
					ela_wlan.desc->ctx_arg);
		ela_wlan.ctx2 = ela_wlan.desc->ctx2_arg >= 0 ?
			regs_get_kernel_argument(regs, ela_wlan.desc->ctx2_arg) :
			0;
		ela_wlan.send_fn = (void *)p->addr;
		ela_wlan.last_cmd_id = (u32)regs_get_kernel_argument(regs,
					ela_wlan.desc->cmd_arg);
		ela_wlan.captured = 1;
		ela_wlan.send_count++;
	}
	spin_unlock_irqrestore(&ela_wlan_lock, flags);
	return 0;
}

static int ela_wlan_restart_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long flags;

	(void)p;
	(void)regs;
	spin_lock_irqsave(&ela_wlan_lock, flags);
	ela_wlan.restart_count++;
	ela_wlan.captured = 0;	/* context torn down: require re-capture */
	spin_unlock_irqrestore(&ela_wlan_lock, flags);
	return 0;
}

/* caller holds ela_wlan_mutex */
static void ela_wlan_teardown_locked(void)
{
	unsigned long flags;

	if (!ela_wlan_armed)
		return;
	unregister_kprobe(&ela_wlan_kp_send);
	if (ela_wlan_restart_armed) {
		unregister_kprobe(&ela_wlan_kp_restart);
		ela_wlan_restart_armed = false;
	}
	ela_wlan_armed = false;
	spin_lock_irqsave(&ela_wlan_lock, flags);
	memset(&ela_wlan, 0, sizeof(ela_wlan));
	spin_unlock_irqrestore(&ela_wlan_lock, flags);
}

static void ela_wlan_shutdown(void)
{
	mutex_lock(&ela_wlan_mutex);
	ela_wlan_teardown_locked();
	mutex_unlock(&ela_wlan_mutex);
}

static const struct ela_wlan_driver_desc *ela_wlan_find(u32 id)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ela_wlan_drivers); i++)
		if (ela_wlan_drivers[i].id == id)
			return &ela_wlan_drivers[i];
	return NULL;
}

static long ela_ioctl_wlan_attach(unsigned long arg)
{
	struct ela_kmod_wlan_attach req;
	const struct ela_wlan_driver_desc *desc;
	unsigned long flags;
	int ret, i;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	desc = ela_wlan_find(req.driver);
	if (!desc)
		return -ENODEV;

	mutex_lock(&ela_wlan_mutex);
	if (ela_wlan_armed) {
		ret = (ela_wlan.desc == desc) ? 0 : -EBUSY;
		goto out;
	}
	memset(&ela_wlan_kp_send, 0, sizeof(ela_wlan_kp_send));
	ela_wlan_kp_send.symbol_name = desc->send_symbol;
	ela_wlan_kp_send.pre_handler = ela_wlan_send_pre;

	spin_lock_irqsave(&ela_wlan_lock, flags);
	memset(&ela_wlan, 0, sizeof(ela_wlan));
	ela_wlan.desc = desc;
	spin_unlock_irqrestore(&ela_wlan_lock, flags);

	ret = register_kprobe(&ela_wlan_kp_send);
	if (ret)		/* driver not loaded / symbol absent */
		goto fail;

	/* Best-effort: hook the first restart/crash symbol that resolves for
	 * the loaded chip. Without it, injection still works but the crash
	 * oracle (restart_count) stays at zero. */
	ela_wlan_restart_armed = false;
	for (i = 0; i < ELA_WLAN_MAX_RESTART_SYMS && desc->restart_symbols[i]; i++) {
		memset(&ela_wlan_kp_restart, 0, sizeof(ela_wlan_kp_restart));
		ela_wlan_kp_restart.symbol_name = desc->restart_symbols[i];
		ela_wlan_kp_restart.pre_handler = ela_wlan_restart_pre;
		if (register_kprobe(&ela_wlan_kp_restart) == 0) {
			ela_wlan_restart_armed = true;
			break;
		}
	}
	ela_wlan_armed = true;
	ret = 0;
	goto out;
fail:
	spin_lock_irqsave(&ela_wlan_lock, flags);
	ela_wlan.desc = NULL;
	spin_unlock_irqrestore(&ela_wlan_lock, flags);
out:
	mutex_unlock(&ela_wlan_mutex);
	return ret;
}

static long ela_ioctl_wlan_detach(unsigned long arg)
{
	struct ela_kmod_wlan_attach req;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	ela_wlan_shutdown();
	return 0;
}

static long ela_ioctl_wlan_status(unsigned long arg)
{
	struct ela_kmod_wlan_status req;
	unsigned long flags;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	spin_lock_irqsave(&ela_wlan_lock, flags);
	req.driver = ela_wlan.desc ? ela_wlan.desc->id : 0;
	req.captured = ela_wlan.captured;
	req.last_cmd_id = ela_wlan.last_cmd_id;
	req.send_count = ela_wlan.send_count;
	req.inject_count = ela_wlan.inject_count;
	req.restart_count = ela_wlan.restart_count;
	spin_unlock_irqrestore(&ela_wlan_lock, flags);
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

static long ela_ioctl_wlan_inject(unsigned long arg)
{
	struct ela_kmod_wlan_inject req;
	const struct ela_wlan_driver_desc *desc;
	void *ctx, *send_fn, *kbuf;
	unsigned long ctx2, flags;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != ELA_KMOD_ABI_VERSION)
		return -EINVAL;
	if (req.len > ELA_KMOD_WLAN_MAX_CMD)
		return -EINVAL;

	kbuf = NULL;
	if (req.len) {
		kbuf = memdup_user((const void __user *)(uintptr_t)req.data,
				   req.len);
		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);
	}

	spin_lock_irqsave(&ela_wlan_lock, flags);
	desc = ela_wlan.desc;
	ctx = ela_wlan.ctx;
	ctx2 = ela_wlan.ctx2;
	send_fn = ela_wlan.send_fn;
	if (!desc || !ela_wlan.captured || !ctx || !send_fn) {
		spin_unlock_irqrestore(&ela_wlan_lock, flags);
		kfree(kbuf);
		return -EAGAIN;		/* not captured: generate driver traffic */
	}
	ela_wlan.inject_count++;
	spin_unlock_irqrestore(&ela_wlan_lock, flags);

	/* Call outside the lock: the driver send path may sleep on tx credits
	 * and will re-enter our send kprobe. */
	ret = desc->inject(ctx, ctx2, send_fn, req.cmd_id, kbuf, req.len);
	kfree(kbuf);

	req.send_ret = ret;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

#else /* !CONFIG_KPROBES: shim needs kprobes to resolve/capture the driver */

static long ela_ioctl_wlan_attach(unsigned long arg) { (void)arg; return -EOPNOTSUPP; }
static long ela_ioctl_wlan_detach(unsigned long arg) { (void)arg; return -EOPNOTSUPP; }
static long ela_ioctl_wlan_status(unsigned long arg) { (void)arg; return -EOPNOTSUPP; }
static long ela_ioctl_wlan_inject(unsigned long arg) { (void)arg; return -EOPNOTSUPP; }
static inline void ela_wlan_shutdown(void) {}

#endif /* CONFIG_KPROBES */

static long ela_kmod_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ela_file_state *state = file->private_data;

	switch (cmd) {
	case ELA_IOC_READ_PHYS:
		return ela_ioctl_phys(arg, false);
	case ELA_IOC_WRITE_PHYS:
		return ela_ioctl_phys(arg, true);
	case ELA_IOC_READ_MMIO:
		return ela_ioctl_mmio(arg, false);
	case ELA_IOC_WRITE_MMIO:
		return ela_ioctl_mmio(arg, true);
	case ELA_IOC_PCI_READ:
		return ela_ioctl_pci_cfg(arg, false);
	case ELA_IOC_PCI_WRITE:
		return ela_ioctl_pci_cfg(arg, true);
	case ELA_IOC_PORT_READ:
		return ela_ioctl_ioport(arg, false);
	case ELA_IOC_PORT_WRITE:
		return ela_ioctl_ioport(arg, true);
	case ELA_IOC_ALLOC_PHYS:
		return ela_ioctl_alloc_phys(state, arg);
	case ELA_IOC_FREE_PHYS:
		return ela_ioctl_free_phys(state, arg);
	case ELA_IOC_VA2PA:
		return ela_ioctl_va2pa(arg);
	case ELA_IOC_SPI_GET:
		return ela_ioctl_spi_get(arg);
	case ELA_IOC_SPI_MTD_GET:
		return ela_ioctl_spi_mtd_get(arg);
	case ELA_IOC_SPI_MTD_READ:
		return ela_ioctl_spi_mtd_read(arg);
	case ELA_IOC_NAND_MTD_GET:
		return ela_ioctl_nand_mtd_get(arg);
	case ELA_IOC_NAND_MTD_READ:
		return ela_ioctl_nand_mtd_read(arg);
	case ELA_IOC_EMMC_GET:
		return ela_ioctl_emmc_get(arg);
	case ELA_IOC_EMMC_READ:
		return ela_ioctl_emmc_read(arg);
	case ELA_IOC_OROM_GET:
		return ela_ioctl_orom_get(arg);
	case ELA_IOC_OROM_READ:
		return ela_ioctl_orom_read(arg);
	case ELA_IOC_USB_GET:
		return ela_ioctl_usb_get(arg);
	case ELA_IOC_USB_RESET:
		return ela_ioctl_usb_reset(arg);
	case ELA_IOC_USB_PORT_GET:
		return ela_ioctl_usb_port_get(arg);
	case ELA_IOC_USB_PORT_ACTION:
		return ela_ioctl_usb_port_action(arg);
	case ELA_IOC_USB_DESCRIPTORS:
		return ela_ioctl_usb_descriptors(arg);
	case ELA_IOC_WLAN_ATTACH:
		return ela_ioctl_wlan_attach(arg);
	case ELA_IOC_WLAN_DETACH:
		return ela_ioctl_wlan_detach(arg);
	case ELA_IOC_WLAN_STATUS:
		return ela_ioctl_wlan_status(arg);
	case ELA_IOC_WLAN_INJECT:
		return ela_ioctl_wlan_inject(arg);
	default:
		return -ENOTTY;
	}
}

static int ela_kmod_open(struct inode *inode, struct file *file)
{
	struct ela_file_state *state;

	/* Same bar as /dev/mem: raw I/O capability, not just file mode. */
	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	state = kmalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	mutex_init(&state->lock);
	INIT_LIST_HEAD(&state->allocations);
	file->private_data = state;
	return 0;
}

static int ela_kmod_release(struct inode *inode, struct file *file)
{
	struct ela_file_state *state = file->private_data;
	struct ela_phys_alloc *alloc;
	struct ela_phys_alloc *tmp;

	list_for_each_entry_safe(alloc, tmp, &state->allocations, node) {
		list_del(&alloc->node);
		free_pages(alloc->virt, alloc->order);
		kfree(alloc);
	}
	mutex_destroy(&state->lock);
	kfree(state);
	return 0;
}

static const struct file_operations ela_kmod_fops = {
	.owner = THIS_MODULE,
	.open = ela_kmod_open,
	.release = ela_kmod_release,
	.unlocked_ioctl = ela_kmod_ioctl,
#ifdef CONFIG_COMPAT
	/* The ABI structs are fixed-size and 64-bit only, so 32-bit userspace
	 * on a 64-bit kernel needs no translation. */
	.compat_ioctl = ela_kmod_ioctl,
#endif
};

static struct miscdevice ela_kmod_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = ELA_KMOD_DEVICE_NAME,
	.fops = &ela_kmod_fops,
	.mode = 0600,
};

static int __init ela_kmod_init(void)
{
	int rc;

#ifdef ELA_HAVE_MTD
	register_mtd_user(&ela_nand_mtd_notifier);
#endif
	rc = misc_register(&ela_kmod_dev);

	if (rc) {
#ifdef ELA_HAVE_MTD
		unregister_mtd_user(&ela_nand_mtd_notifier);
		ela_nand_entries_clear();
#endif
		pr_err("ela_kmod: misc_register failed: %d\n", rc);
		return rc;
	}
	pr_info("ela_kmod: loaded (abi %u, %s)\n",
		ELA_KMOD_ABI_VERSION, ELA_KMOD_DEVICE_PATH);
	return 0;
}

static void __exit ela_kmod_exit(void)
{
	ela_wlan_shutdown();	/* unregister any WLAN-shim kprobes */
	misc_deregister(&ela_kmod_dev);
#ifdef ELA_HAVE_MTD
	unregister_mtd_user(&ela_nand_mtd_notifier);
	ela_nand_entries_clear();
#endif
	pr_info("ela_kmod: unloaded\n");
}

module_init(ela_kmod_init);
module_exit(ela_kmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicholas Starke");
MODULE_DESCRIPTION("embedded_linux_audit host inspection module");
MODULE_VERSION("0.9");
