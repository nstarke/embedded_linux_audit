// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

#include <stdint.h>

static void test_uboot_get_mtd_index_variants(void)
{
	char idx[16];

	ELA_ASSERT_INT_EQ(0, uboot_get_mtd_index("/dev/mtd7", idx, sizeof(idx)));
	ELA_ASSERT_STR_EQ("7", idx);
	ELA_ASSERT_INT_EQ(0, uboot_get_mtd_index("/dev/mtdblock12", idx, sizeof(idx)));
	ELA_ASSERT_STR_EQ("12", idx);
	ELA_ASSERT_INT_EQ(0, uboot_get_mtd_index("mtd5ro", idx, sizeof(idx)));
	ELA_ASSERT_STR_EQ("5", idx);
	ELA_ASSERT_INT_EQ(-1, uboot_get_mtd_index("/dev/mtdro", idx, sizeof(idx)));
	ELA_ASSERT_INT_EQ(-1, uboot_get_mtd_index("/dev/mtd7foo", idx, sizeof(idx)));
	ELA_ASSERT_INT_EQ(-1, uboot_get_mtd_index("/dev/mmcblk0", idx, sizeof(idx)));
}

static void test_uboot_get_ubi_indices_variants(void)
{
	unsigned int ubi = 0;
	unsigned int vol = 0;

	ELA_ASSERT_INT_EQ(0, uboot_get_ubi_indices("/dev/ubi2_9", &ubi, &vol));
	ELA_ASSERT_INT_EQ(2, ubi);
	ELA_ASSERT_INT_EQ(9, vol);

	ELA_ASSERT_INT_EQ(0, uboot_get_ubi_indices("ubiblock10_3", &ubi, &vol));
	ELA_ASSERT_INT_EQ(10, ubi);
	ELA_ASSERT_INT_EQ(3, vol);

	ELA_ASSERT_INT_EQ(-1, uboot_get_ubi_indices("/dev/ubi4", &ubi, &vol));
	ELA_ASSERT_INT_EQ(-1, uboot_get_ubi_indices("/dev/ubi4_1extra", &ubi, &vol));
	ELA_ASSERT_INT_EQ(-1, uboot_get_ubi_indices("/dev/mmcblk0", &ubi, &vol));
}

static void test_uboot_parse_major_minor_text(void)
{
	unsigned int major = 0;
	unsigned int minor = 0;

	ELA_ASSERT_INT_EQ(0, uboot_parse_major_minor("31:7\n", &major, &minor));
	ELA_ASSERT_INT_EQ(31, major);
	ELA_ASSERT_INT_EQ(7, minor);

	ELA_ASSERT_INT_EQ(0, uboot_parse_major_minor("8:0", &major, &minor));
	ELA_ASSERT_INT_EQ(8, major);
	ELA_ASSERT_INT_EQ(0, minor);

	ELA_ASSERT_INT_EQ(-1, uboot_parse_major_minor("31:7 extra", &major, &minor));
	ELA_ASSERT_INT_EQ(-1, uboot_parse_major_minor("31", &major, &minor));
	ELA_ASSERT_INT_EQ(-1, uboot_parse_major_minor(NULL, &major, &minor));
}

static void test_uboot_block_name_detection(void)
{
	ELA_ASSERT_TRUE(uboot_is_sd_block_name("sda"));
	ELA_ASSERT_TRUE(uboot_is_sd_block_name("sda12"));
	ELA_ASSERT_FALSE(uboot_is_sd_block_name("sd"));
	ELA_ASSERT_FALSE(uboot_is_sd_block_name("sdA1"));
	ELA_ASSERT_FALSE(uboot_is_sd_block_name("sdaa"));

	ELA_ASSERT_TRUE(uboot_is_emmc_block_name("mmcblk0"));
	ELA_ASSERT_TRUE(uboot_is_emmc_block_name("mmcblk12p3"));
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name("mmcblk"));
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name("mmcblk0p"));
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name("mmcblk0px"));
}

static void test_ela_read_be32_decodes_big_endian_words(void)
{
	const uint8_t bytes[] = { 0x12, 0x34, 0x56, 0x78 };

	ELA_ASSERT_INT_EQ(0x12345678U, ela_read_be32(bytes));
}

int run_device_scan_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "uboot_get_mtd_index_variants", test_uboot_get_mtd_index_variants },
		{ "uboot_get_ubi_indices_variants", test_uboot_get_ubi_indices_variants },
		{ "uboot_parse_major_minor_text", test_uboot_parse_major_minor_text },
		{ "uboot_block_name_detection", test_uboot_block_name_detection },
		{ "ela_read_be32_decodes_big_endian_words", test_ela_read_be32_decodes_big_endian_words },
	};

	return ela_run_test_suite("device_scan", cases, sizeof(cases) / sizeof(cases[0]));
}
