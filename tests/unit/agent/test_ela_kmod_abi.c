// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * ABI lockdown for kmod/ela_ioctl.h, the ioctl contract between the agent
 * and the ela_kmod kernel module. The struct layout and ioctl numbers are
 * wire format: the module may be compiled weeks later against a different
 * kernel than the agent talking to it, so any size/offset change here is a
 * breaking change that must bump ELA_KMOD_ABI_VERSION.
 */

#include "../../../kmod/ela_ioctl.h"
#include "test_harness.h"

#include <stddef.h>

static void test_read_phys_struct_layout(void)
{
	/* Fixed 32-byte layout: 2x u32 + 3x u64, no implicit padding. */
	ELA_ASSERT_INT_EQ(32, sizeof(struct ela_kmod_read_phys));
	ELA_ASSERT_INT_EQ(0, offsetof(struct ela_kmod_read_phys, abi_version));
	ELA_ASSERT_INT_EQ(4, offsetof(struct ela_kmod_read_phys, flags));
	ELA_ASSERT_INT_EQ(8, offsetof(struct ela_kmod_read_phys, phys_addr));
	ELA_ASSERT_INT_EQ(16, offsetof(struct ela_kmod_read_phys, length));
	ELA_ASSERT_INT_EQ(24, offsetof(struct ela_kmod_read_phys, buf));
}

static void test_write_phys_struct_layout(void)
{
	/* The write struct mirrors the read struct exactly; the module relies
	 * on that to validate both ioctls through one code path. */
	ELA_ASSERT_INT_EQ(32, sizeof(struct ela_kmod_write_phys));
	ELA_ASSERT_INT_EQ(0, offsetof(struct ela_kmod_write_phys, abi_version));
	ELA_ASSERT_INT_EQ(4, offsetof(struct ela_kmod_write_phys, flags));
	ELA_ASSERT_INT_EQ(8, offsetof(struct ela_kmod_write_phys, phys_addr));
	ELA_ASSERT_INT_EQ(16, offsetof(struct ela_kmod_write_phys, length));
	ELA_ASSERT_INT_EQ(24, offsetof(struct ela_kmod_write_phys, buf));
}

static void test_mmio_struct_layout(void)
{
	ELA_ASSERT_INT_EQ(24, sizeof(struct ela_kmod_mmio));
	ELA_ASSERT_INT_EQ(0, offsetof(struct ela_kmod_mmio, abi_version));
	ELA_ASSERT_INT_EQ(4, offsetof(struct ela_kmod_mmio, width));
	ELA_ASSERT_INT_EQ(8, offsetof(struct ela_kmod_mmio, phys_addr));
	ELA_ASSERT_INT_EQ(16, offsetof(struct ela_kmod_mmio, value));
}

static void test_pci_cfg_struct_layout(void)
{
	ELA_ASSERT_INT_EQ(24, sizeof(struct ela_kmod_pci_cfg));
	ELA_ASSERT_INT_EQ(0, offsetof(struct ela_kmod_pci_cfg, abi_version));
	ELA_ASSERT_INT_EQ(4, offsetof(struct ela_kmod_pci_cfg, width));
	ELA_ASSERT_INT_EQ(8, offsetof(struct ela_kmod_pci_cfg, domain));
	ELA_ASSERT_INT_EQ(12, offsetof(struct ela_kmod_pci_cfg, bus));
	ELA_ASSERT_INT_EQ(13, offsetof(struct ela_kmod_pci_cfg, device));
	ELA_ASSERT_INT_EQ(14, offsetof(struct ela_kmod_pci_cfg, function));
	ELA_ASSERT_INT_EQ(15, offsetof(struct ela_kmod_pci_cfg, pad));
	ELA_ASSERT_INT_EQ(16, offsetof(struct ela_kmod_pci_cfg, offset));
	ELA_ASSERT_INT_EQ(20, offsetof(struct ela_kmod_pci_cfg, value));
}

static void test_physctl_struct_layouts(void)
{
	ELA_ASSERT_INT_EQ(32, sizeof(struct ela_kmod_alloc_phys));
	ELA_ASSERT_INT_EQ(8, offsetof(struct ela_kmod_alloc_phys, length));
	ELA_ASSERT_INT_EQ(16, offsetof(struct ela_kmod_alloc_phys, max_phys_addr));
	ELA_ASSERT_INT_EQ(24, offsetof(struct ela_kmod_alloc_phys, phys_addr));

	ELA_ASSERT_INT_EQ(16, sizeof(struct ela_kmod_free_phys));
	ELA_ASSERT_INT_EQ(8, offsetof(struct ela_kmod_free_phys, phys_addr));

	ELA_ASSERT_INT_EQ(24, sizeof(struct ela_kmod_va2pa));
	ELA_ASSERT_INT_EQ(8, offsetof(struct ela_kmod_va2pa, virt_addr));
	ELA_ASSERT_INT_EQ(16, offsetof(struct ela_kmod_va2pa, phys_addr));
}

static void test_abi_constants(void)
{
	ELA_ASSERT_INT_EQ(1, ELA_KMOD_ABI_VERSION);
	ELA_ASSERT_INT_EQ(0xE5, ELA_KMOD_IOC_MAGIC);
	ELA_ASSERT_TRUE(ELA_KMOD_MAX_READ == 16UL * 1024UL * 1024UL);
	ELA_ASSERT_STR_EQ("/dev/ela_physmem", ELA_KMOD_DEVICE_PATH);
	/* All defined flags are inside the accepted mask. */
	ELA_ASSERT_INT_EQ(ELA_KMOD_READ_F_ALL,
			  ELA_KMOD_READ_F_ALL | ELA_KMOD_READ_F_UNCACHED);
}

static void test_ioctl_number_is_stable(void)
{
	/* _IOW(0xE5, 0x01, 32-byte struct): direction/size/magic/nr all feed
	 * the encoded number, so this single check pins the whole encoding.
	 * The literal differs across OS ioctl encodings; derive it the same
	 * way the kernel will but assert the components. */
	static const struct { unsigned long cmd; int nr; } cmds[] = {
		{ ELA_IOC_READ_PHYS, 0x01 },
		{ ELA_IOC_WRITE_PHYS, 0x02 },
		{ ELA_IOC_READ_MMIO, 0x03 },
		{ ELA_IOC_WRITE_MMIO, 0x04 },
		{ ELA_IOC_ALLOC_PHYS, 0x05 },
		{ ELA_IOC_FREE_PHYS, 0x06 },
		{ ELA_IOC_VA2PA, 0x07 },
		{ ELA_IOC_PCI_READ, 0x20 },
		{ ELA_IOC_PCI_WRITE, 0x21 },
	};
	size_t i;

	for (i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
		ELA_ASSERT_INT_EQ(0xE5, (int)((cmds[i].cmd >> 8) & 0xff));
		ELA_ASSERT_INT_EQ(cmds[i].nr, (int)(cmds[i].cmd & 0xff));
	}
}

int run_ela_kmod_abi_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "abi/read_phys_layout", test_read_phys_struct_layout },
		{ "abi/write_phys_layout", test_write_phys_struct_layout },
		{ "abi/mmio_layout", test_mmio_struct_layout },
		{ "abi/pci_cfg_layout", test_pci_cfg_struct_layout },
		{ "abi/physctl_layouts", test_physctl_struct_layouts },
		{ "abi/constants", test_abi_constants },
		{ "abi/ioctl_number", test_ioctl_number_is_stable },
	};

	return ela_run_test_suite("ela_kmod_abi", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
