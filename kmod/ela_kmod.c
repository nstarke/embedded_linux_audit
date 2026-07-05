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
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/version.h>
#ifdef CONFIG_PCI
# include <linux/pci.h>
#endif
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

#include "ela_ioctl.h"

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
	case ELA_IOC_ALLOC_PHYS:
		return ela_ioctl_alloc_phys(state, arg);
	case ELA_IOC_FREE_PHYS:
		return ela_ioctl_free_phys(state, arg);
	case ELA_IOC_VA2PA:
		return ela_ioctl_va2pa(arg);
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
	int rc = misc_register(&ela_kmod_dev);

	if (rc) {
		pr_err("ela_kmod: misc_register failed: %d\n", rc);
		return rc;
	}
	pr_info("ela_kmod: loaded (abi %u, %s)\n",
		ELA_KMOD_ABI_VERSION, ELA_KMOD_DEVICE_PATH);
	return 0;
}

static void __exit ela_kmod_exit(void)
{
	misc_deregister(&ela_kmod_dev);
	pr_info("ela_kmod: unloaded\n");
}

module_init(ela_kmod_init);
module_exit(ela_kmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicholas Starke");
MODULE_DESCRIPTION("embedded_linux_audit host inspection module");
MODULE_VERSION("0.3");
