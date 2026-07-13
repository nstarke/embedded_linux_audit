/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * ela_kmod userspace ABI: the ioctl interface of /dev/ela_physmem.
 *
 * This header is shared verbatim between the kernel module (kmod/) and the
 * agent (agent/linux/), so it must compile as both kernel and userspace C:
 * only fixed-width types, no kernel-only headers beyond linux/types.h /
 * linux/ioctl.h (which userspace gets via its libc kernel headers).
 *
 * ABI rules:
 *  - Every request struct starts with abi_version (ELA_KMOD_ABI_VERSION at
 *    build time on both sides); the module rejects versions it doesn't know.
 *  - Structs are fixed-size with explicit padding and 64-bit members only,
 *    so 32-bit userspace against a 64-bit kernel needs no compat layer.
 *  - Userspace pointers travel as __u64 (cast through uintptr_t), never as
 *    bare pointers.
 *  - New operations append new ioctl numbers; existing numbers never change
 *    meaning. The numbers below reserve the planned chipsec-style surface so
 *    downstream tooling can hard-code them early.
 */

#ifndef ELA_IOCTL_H
#define ELA_IOCTL_H

#ifdef __KERNEL__
# include <linux/types.h>
# include <linux/ioctl.h>
#else
# include <stdint.h>
# include <sys/ioctl.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint8_t __u8;
#endif

#define ELA_KMOD_ABI_VERSION 1U

#define ELA_KMOD_DEVICE_NAME "ela_physmem"
#define ELA_KMOD_DEVICE_PATH "/dev/" ELA_KMOD_DEVICE_NAME

/* Hard per-call ceiling on read length; larger reads must be chunked by the
 * caller. Keeps the module's bounce buffer and mapping windows bounded. */
#define ELA_KMOD_MAX_READ (16UL * 1024UL * 1024UL)

/*
 * Read `length` bytes of physical memory starting at `phys_addr` into the
 * userspace buffer at `buf` (a userspace virtual address cast to __u64).
 *
 * flags: ELA_KMOD_READ_F_* below. Default (0) requires the whole range to be
 * real RAM and moves it through the kernel's EXISTING mapping of that RAM (kmap
 * / the linear map), never a fresh ioremap: RAM is already mapped, and a second
 * differently-cached alias of it is illegal on ARMv6+/v7 and crashes the box. A
 * non-RAM range is refused with ENXIO. ELA_KMOD_READ_F_UNCACHED instead maps the
 * range uncached via ioremap (no RAM check) for deliberate device/MMIO access
 * (side-effect-free only if the target tolerates reads, as with chipsec) — at
 * the caller's risk.
 *
 * Returns 0 on success. Errors:
 *   EINVAL  bad abi_version, zero/oversized length, or unknown flags
 *   EFAULT  buf is not writable for `length` bytes
 *   ENXIO   the physical range cannot be mapped, or (default path) is not RAM
 */
struct ela_kmod_read_phys {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 flags;         /* in: ELA_KMOD_READ_F_* */
	__u64 phys_addr;     /* in: physical address to read from */
	__u64 length;        /* in: bytes to read (1..ELA_KMOD_MAX_READ) */
	__u64 buf;           /* in: userspace destination, cast to __u64 */
};

#define ELA_KMOD_READ_F_UNCACHED 0x1U
#define ELA_KMOD_READ_F_ALL      (ELA_KMOD_READ_F_UNCACHED)

/*
 * Write `length` bytes from the userspace buffer at `buf` to physical memory
 * starting at `phys_addr`. Same layout, flags, limits, and error returns as
 * the read op (EFAULT here means `buf` is not readable). Writes to live
 * physical memory are inherently dangerous; the module performs them exactly
 * as requested with no target validation beyond mappability.
 */
struct ela_kmod_write_phys {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 flags;         /* in: ELA_KMOD_READ_F_* (shared flag space) */
	__u64 phys_addr;     /* in: physical address to write to */
	__u64 length;        /* in: bytes to write (1..ELA_KMOD_MAX_READ) */
	__u64 buf;           /* in: userspace source, cast to __u64 */
};

/*
 * Sized MMIO register access (chipsec RDMMIO/WRMMIO port). Unlike the bulk
 * READ/WRITE_PHYS ops, these perform ONE naturally-aligned device-width
 * access (1/2/4/8 bytes) through an uncached mapping — the difference
 * matters for device registers with read/write side effects, where a bulk
 * memcpy's access pattern is undefined. `value` carries the data in both
 * directions (zero-extended on reads).
 *
 * Errors: EINVAL (bad width, misaligned addr), ENXIO (unmappable),
 * EOPNOTSUPP (width 8 on kernels without a usable 64-bit accessor).
 */
struct ela_kmod_mmio {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 width;         /* in: access size in bytes: 1, 2, 4, or 8 */
	__u64 phys_addr;     /* in: physical register address (width-aligned) */
	__u64 value;         /* in (write) / out (read): register value */
};

/*
 * PCI configuration space access (chipsec RDPCI/WRPCI port). Implemented
 * with the kernel's portable PCI accessors — not the x86 0xCF8/0xCFC port
 * mechanism chipsec uses — so it works on any arch with a PCI host bridge
 * (and honors extended config space: offsets up to 4095 where supported).
 * The addressed function does not need a bound driver, but its bus must
 * have been enumerated by the kernel.
 *
 * Errors: EINVAL (bad width/offset/bdf), ENODEV (no such device).
 */
struct ela_kmod_pci_cfg {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 width;         /* in: access size in bytes: 1, 2, or 4 */
	__u32 domain;        /* in: PCI domain/segment (0 on most embedded) */
	__u8  bus;           /* in: bus number */
	__u8  device;        /* in: device number (0-31) */
	__u8  function;      /* in: function number (0-7) */
	__u8  pad;           /* zero */
	__u32 offset;        /* in: config space offset (width-aligned) */
	__u32 value;         /* in (write) / out (read): register value */
};

/*
 * Allocate a physically-contiguous, zeroed buffer inside the kernel
 * (chipsec ALLOC_PHYSMEM port). Used to stage DMA-visible scratch buffers
 * at known physical addresses. Only the physical address is returned —
 * chipsec also leaks the kernel virtual address to userspace; we do not.
 * Read/write the buffer through the READ/WRITE_PHYS ops.
 *
 * Allocations are tracked per open file descriptor and freed automatically
 * when it closes (chipsec leaks them until module unload).
 *
 * `max_phys_addr` bounds the acceptable physical placement (e.g. below
 * 4 GiB for a 32-bit DMA master); 0 means no constraint.
 */
struct ela_kmod_alloc_phys {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 pad;           /* zero */
	__u64 length;        /* in: bytes (1..ELA_KMOD_MAX_READ) */
	__u64 max_phys_addr; /* in: highest acceptable phys addr; 0 = any */
	__u64 phys_addr;     /* out: physical address of the buffer */
};

/* Free one allocation made on this file descriptor, by its physical
 * address. Errors: ENOENT (not an allocation of this fd). */
struct ela_kmod_free_phys {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 pad;           /* zero */
	__u64 phys_addr;     /* in: address returned by ELA_IOC_ALLOC_PHYS */
};

/*
 * Translate a kernel linear-map virtual address to physical (chipsec VA2PA
 * port). Only lowmem/linear-map addresses translate (vmalloc and userspace
 * addresses return EINVAL); primarily a debugging aid.
 */
struct ela_kmod_va2pa {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 pad;           /* zero */
	__u64 virt_addr;     /* in: kernel virtual address */
	__u64 phys_addr;     /* out: physical address */
};

#define ELA_KMOD_SPI_NAME_LEN 32U
#define ELA_KMOD_SPI_DRIVER_LEN 32U
#define ELA_KMOD_MTD_NAME_LEN 64U
#define ELA_KMOD_SPI_MAX_READ (1024UL * 1024UL)
#define ELA_KMOD_NAND_MAX_READ (1024UL * 1024UL)
#define ELA_KMOD_EMMC_NAME_LEN 32U
#define ELA_KMOD_EMMC_MAX_READ (1024UL * 1024UL)
#define ELA_KMOD_OROM_MAX_READ (1024UL * 1024UL)

/* Return one kernel-enumerated SPI device by zero-based ordinal. ENOENT marks
 * the end of the list. The strings are always NUL terminated. */
struct ela_kmod_spi_device {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 ordinal;       /* in: zero-based enumeration position */
	__u32 mode;          /* out: SPI mode flags */
	__u32 max_speed_hz;  /* out: configured maximum clock */
	__u32 bits_per_word; /* out */
	__u32 pad;           /* zero */
	char device_name[ELA_KMOD_SPI_NAME_LEN];
	char modalias[ELA_KMOD_SPI_NAME_LEN];
	char driver[ELA_KMOD_SPI_DRIVER_LEN];
};

/* Return one MTD device whose kernel device ancestry contains an SPI device.
 * The mtd_index is the stable selector accepted by ELA_IOC_SPI_MTD_READ. */
struct ela_kmod_spi_mtd {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 ordinal;       /* in: zero-based enumeration position */
	__u32 mtd_index;     /* out */
	__u32 writesize;     /* out */
	__u32 erasesize;     /* out */
	__u32 pad;           /* zero */
	__u64 size;          /* out: bytes */
	char spi_name[ELA_KMOD_SPI_NAME_LEN];
	char mtd_name[ELA_KMOD_MTD_NAME_LEN];
};

/* Read bytes through the kernel MTD layer after verifying that mtd_index is
 * still attached beneath an SPI device. Reads larger than the per-call limit
 * are chunked by userspace. */
struct ela_kmod_spi_mtd_read {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 mtd_index;     /* in: from ELA_IOC_SPI_MTD_GET */
	__u64 offset;        /* in */
	__u64 length;        /* in: 1..ELA_KMOD_SPI_MAX_READ */
	__u64 buf;           /* in: userspace destination, cast to __u64 */
};

/* Return one NAND/MLC-NAND MTD device by zero-based ordinal. This includes
 * parallel raw NAND and SPI-NAND devices registered with the MTD core. */
struct ela_kmod_nand_mtd {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 ordinal;       /* in: zero-based enumeration position */
	__u32 mtd_index;     /* out */
	__u32 type;          /* out: MTD_NANDFLASH or MTD_MLCNANDFLASH */
	__u32 writesize;     /* out: main-area page size */
	__u32 erasesize;     /* out: eraseblock size */
	__u32 oobsize;       /* out: OOB bytes per page */
	__u32 ecc_strength;  /* out: correctable bits per ECC step */
	__u64 size;          /* out: main-area bytes */
	char mtd_name[ELA_KMOD_MTD_NAME_LEN];
};

/* Read corrected NAND main-area bytes. Marked bad eraseblocks are represented
 * by 0xff bytes so the output preserves physical offsets. bad_blocks reports
 * how many distinct bad eraseblocks intersected this request. */
struct ela_kmod_nand_mtd_read {
	__u32 abi_version;   /* in: ELA_KMOD_ABI_VERSION */
	__u32 mtd_index;     /* in: from ELA_IOC_NAND_MTD_GET */
	__u64 offset;        /* in */
	__u64 length;        /* in: 1..ELA_KMOD_NAND_MAX_READ */
	__u64 buf;           /* in: userspace destination, cast to __u64 */
	__u32 bad_blocks;    /* out */
	__u32 pad;           /* zero */
};

/* Return one whole eMMC user-area block device by zero-based ordinal. SD
 * cards, DOS/GPT partitions, eMMC boot areas, and RPMB are excluded. */
struct ela_kmod_emmc_device {
	__u32 abi_version;        /* in: ELA_KMOD_ABI_VERSION */
	__u32 ordinal;            /* in: zero-based enumeration position */
	__u32 major;              /* out: block device major */
	__u32 minor;              /* out: whole-disk minor */
	__u32 logical_block_size; /* out: bytes */
	__u32 pad;                /* zero */
	__u64 size;               /* out: user-area bytes */
	char disk_name[ELA_KMOD_EMMC_NAME_LEN];
};

/* Read bytes from an eMMC user area through the kernel block layer. */
struct ela_kmod_emmc_read {
	__u32 abi_version; /* in: ELA_KMOD_ABI_VERSION */
	__u32 major;       /* in: from ELA_IOC_EMMC_GET */
	__u32 minor;       /* in: from ELA_IOC_EMMC_GET */
	__u32 pad;         /* zero */
	__u64 offset;      /* in */
	__u64 length;      /* in: 1..ELA_KMOD_EMMC_MAX_READ */
	__u64 buf;         /* in: userspace destination, cast to __u64 */
};

/* Return one PCI function whose expansion ROM can be mapped by the kernel. */
struct ela_kmod_orom_device {
	__u32 abi_version; /* in: ELA_KMOD_ABI_VERSION */
	__u32 ordinal;     /* in: zero-based enumeration position */
	__u32 domain;      /* out: PCI domain */
	__u32 bus;         /* out */
	__u32 device;      /* out */
	__u32 function;    /* out */
	__u32 vendor_id;   /* out */
	__u32 device_id;   /* out */
	__u32 class_code;  /* out: 24-bit PCI class */
	__u32 pad;         /* zero */
	__u64 size;        /* out: mapped ROM bytes */
};

/* Read bytes from a PCI expansion ROM through pci_map_rom(). */
struct ela_kmod_orom_read {
	__u32 abi_version; /* in: ELA_KMOD_ABI_VERSION */
	__u32 domain;      /* in: from ELA_IOC_OROM_GET */
	__u32 bus;         /* in */
	__u32 device;      /* in */
	__u32 function;    /* in */
	__u32 pad;         /* zero */
	__u64 offset;      /* in */
	__u64 length;      /* in: 1..ELA_KMOD_OROM_MAX_READ */
	__u64 buf;         /* in: userspace destination, cast to __u64 */
};

#define ELA_KMOD_IOC_MAGIC 0xE5

/* Implemented operations. */
#define ELA_IOC_READ_PHYS  _IOW(ELA_KMOD_IOC_MAGIC, 0x01, struct ela_kmod_read_phys)
#define ELA_IOC_WRITE_PHYS _IOW(ELA_KMOD_IOC_MAGIC, 0x02, struct ela_kmod_write_phys)
#define ELA_IOC_READ_MMIO  _IOWR(ELA_KMOD_IOC_MAGIC, 0x03, struct ela_kmod_mmio)
#define ELA_IOC_WRITE_MMIO _IOW(ELA_KMOD_IOC_MAGIC, 0x04, struct ela_kmod_mmio)
#define ELA_IOC_ALLOC_PHYS _IOWR(ELA_KMOD_IOC_MAGIC, 0x05, struct ela_kmod_alloc_phys)
#define ELA_IOC_FREE_PHYS  _IOW(ELA_KMOD_IOC_MAGIC, 0x06, struct ela_kmod_free_phys)
#define ELA_IOC_VA2PA      _IOWR(ELA_KMOD_IOC_MAGIC, 0x07, struct ela_kmod_va2pa)
#define ELA_IOC_PCI_READ   _IOWR(ELA_KMOD_IOC_MAGIC, 0x20, struct ela_kmod_pci_cfg)
#define ELA_IOC_PCI_WRITE  _IOW(ELA_KMOD_IOC_MAGIC, 0x21, struct ela_kmod_pci_cfg)
#define ELA_IOC_SPI_GET      _IOWR(ELA_KMOD_IOC_MAGIC, 0x40, struct ela_kmod_spi_device)
#define ELA_IOC_SPI_MTD_GET  _IOWR(ELA_KMOD_IOC_MAGIC, 0x41, struct ela_kmod_spi_mtd)
#define ELA_IOC_SPI_MTD_READ _IOW(ELA_KMOD_IOC_MAGIC, 0x42, struct ela_kmod_spi_mtd_read)
#define ELA_IOC_NAND_MTD_GET  _IOWR(ELA_KMOD_IOC_MAGIC, 0x50, struct ela_kmod_nand_mtd)
#define ELA_IOC_NAND_MTD_READ _IOWR(ELA_KMOD_IOC_MAGIC, 0x51, struct ela_kmod_nand_mtd_read)
#define ELA_IOC_EMMC_GET       _IOWR(ELA_KMOD_IOC_MAGIC, 0x60, struct ela_kmod_emmc_device)
#define ELA_IOC_EMMC_READ      _IOW(ELA_KMOD_IOC_MAGIC, 0x61, struct ela_kmod_emmc_read)
#define ELA_IOC_OROM_GET       _IOWR(ELA_KMOD_IOC_MAGIC, 0x70, struct ela_kmod_orom_device)
#define ELA_IOC_OROM_READ      _IOW(ELA_KMOD_IOC_MAGIC, 0x71, struct ela_kmod_orom_read)

/*
 * Reserved operation numbers for x86-only chipsec-style ops (not portable
 * to the ARM/MIPS/PowerPC/RISC-V fleet; implemented only if an x86-specific
 * need appears):
 *   0x10  ELA_IOC_RDMSR        model-specific register read (x86)
 *   0x11  ELA_IOC_WRMSR        model-specific register write (x86)
 *   0x30  ELA_IOC_PORT_READ    port I/O read (x86)
 *   0x31  ELA_IOC_PORT_WRITE   port I/O write (x86)
 */

#endif /* ELA_IOCTL_H */
