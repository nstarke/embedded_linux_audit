// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * ela_read_be32
 * ====================================================================== */

static void test_be32_known_value(void)
{
	const uint8_t b[] = { 0x12, 0x34, 0x56, 0x78 };

	ELA_ASSERT_INT_EQ((int)0x12345678u, (int)ela_read_be32(b));
}

static void test_be32_all_zeros(void)
{
	const uint8_t b[] = { 0x00, 0x00, 0x00, 0x00 };

	ELA_ASSERT_INT_EQ(0, (int)ela_read_be32(b));
}

static void test_be32_all_ff(void)
{
	const uint8_t b[] = { 0xFF, 0xFF, 0xFF, 0xFF };

	ELA_ASSERT_INT_EQ((int)0xFFFFFFFFu, (int)ela_read_be32(b));
}

static void test_be32_incremental(void)
{
	const uint8_t b[] = { 0x01, 0x02, 0x03, 0x04 };

	ELA_ASSERT_INT_EQ((int)0x01020304u, (int)ela_read_be32(b));
}

static void test_be32_high_bit_only(void)
{
	const uint8_t b[] = { 0x80, 0x00, 0x00, 0x00 };

	ELA_ASSERT_INT_EQ((int)0x80000000u, (int)ela_read_be32(b));
}

static void test_be32_low_byte_only(void)
{
	const uint8_t b[] = { 0x00, 0x00, 0x00, 0xAB };

	ELA_ASSERT_INT_EQ((int)0x000000ABu, (int)ela_read_be32(b));
}

/* =========================================================================
 * uboot_get_mtd_index
 * ====================================================================== */

static void test_mtd_index_null_idx_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, uboot_get_mtd_index("/dev/mtd7", NULL, 16));
}

static void test_mtd_index_small_buf_returns_minus1(void)
{
	char idx[1];

	/* idx_sz < 2 must be rejected */
	ELA_ASSERT_INT_EQ(-1, uboot_get_mtd_index("/dev/mtd7", idx, 1));
}

static void test_mtd_index_single_digit(void)
{
	char idx[16];

	ELA_ASSERT_INT_EQ(0, uboot_get_mtd_index("/dev/mtd7", idx, sizeof(idx)));
	ELA_ASSERT_STR_EQ("7", idx);
}

static void test_mtd_index_two_digits(void)
{
	char idx[16];

	ELA_ASSERT_INT_EQ(0, uboot_get_mtd_index("/dev/mtd12", idx, sizeof(idx)));
	ELA_ASSERT_STR_EQ("12", idx);
}

static void test_mtd_index_zero(void)
{
	char idx[16];

	ELA_ASSERT_INT_EQ(0, uboot_get_mtd_index("/dev/mtd0", idx, sizeof(idx)));
	ELA_ASSERT_STR_EQ("0", idx);
}

static void test_mtd_index_mtdblock(void)
{
	char idx[16];

	ELA_ASSERT_INT_EQ(0, uboot_get_mtd_index("/dev/mtdblock12", idx, sizeof(idx)));
	ELA_ASSERT_STR_EQ("12", idx);
}

static void test_mtd_index_mtdblock_single_digit(void)
{
	char idx[16];

	ELA_ASSERT_INT_EQ(0, uboot_get_mtd_index("/dev/mtdblock3", idx, sizeof(idx)));
	ELA_ASSERT_STR_EQ("3", idx);
}

static void test_mtd_index_ro_suffix_accepted(void)
{
	char idx[16];

	/* "mtd5ro" is a valid read-only variant */
	ELA_ASSERT_INT_EQ(0, uboot_get_mtd_index("mtd5ro", idx, sizeof(idx)));
	ELA_ASSERT_STR_EQ("5", idx);
}

static void test_mtd_index_no_path_separator(void)
{
	char idx[16];

	/* basename without leading slash */
	ELA_ASSERT_INT_EQ(0, uboot_get_mtd_index("mtd3", idx, sizeof(idx)));
	ELA_ASSERT_STR_EQ("3", idx);
}

static void test_mtd_index_no_digits_returns_minus1(void)
{
	char idx[16];

	ELA_ASSERT_INT_EQ(-1, uboot_get_mtd_index("/dev/mtd", idx, sizeof(idx)));
}

static void test_mtd_index_mtdro_no_digits_returns_minus1(void)
{
	char idx[16];

	ELA_ASSERT_INT_EQ(-1, uboot_get_mtd_index("/dev/mtdro", idx, sizeof(idx)));
}

static void test_mtd_index_extra_suffix_returns_minus1(void)
{
	char idx[16];

	/* suffix other than "ro" is rejected */
	ELA_ASSERT_INT_EQ(-1, uboot_get_mtd_index("/dev/mtd7foo", idx, sizeof(idx)));
}

static void test_mtd_index_non_mtd_prefix_returns_minus1(void)
{
	char idx[16];

	ELA_ASSERT_INT_EQ(-1, uboot_get_mtd_index("/dev/mmcblk0", idx, sizeof(idx)));
}

static void test_mtd_index_mtdblock_no_digits_returns_minus1(void)
{
	char idx[16];

	ELA_ASSERT_INT_EQ(-1, uboot_get_mtd_index("/dev/mtdblock", idx, sizeof(idx)));
}

/* =========================================================================
 * uboot_get_ubi_indices
 * ====================================================================== */

static void test_ubi_null_ubi_out_returns_minus1(void)
{
	unsigned int vol = 0;

	ELA_ASSERT_INT_EQ(-1, uboot_get_ubi_indices("/dev/ubi2_9", NULL, &vol));
}

static void test_ubi_null_vol_out_returns_minus1(void)
{
	unsigned int ubi = 0;

	ELA_ASSERT_INT_EQ(-1, uboot_get_ubi_indices("/dev/ubi2_9", &ubi, NULL));
}

static void test_ubi_simple_path(void)
{
	unsigned int ubi = 0, vol = 0;

	ELA_ASSERT_INT_EQ(0, uboot_get_ubi_indices("/dev/ubi2_9", &ubi, &vol));
	ELA_ASSERT_INT_EQ(2, (int)ubi);
	ELA_ASSERT_INT_EQ(9, (int)vol);
}

static void test_ubi_zero_zero(void)
{
	unsigned int ubi = 0xFF, vol = 0xFF;

	ELA_ASSERT_INT_EQ(0, uboot_get_ubi_indices("/dev/ubi0_0", &ubi, &vol));
	ELA_ASSERT_INT_EQ(0, (int)ubi);
	ELA_ASSERT_INT_EQ(0, (int)vol);
}

static void test_ubi_ubiblock_no_path(void)
{
	unsigned int ubi = 0, vol = 0;

	ELA_ASSERT_INT_EQ(0, uboot_get_ubi_indices("ubiblock10_3", &ubi, &vol));
	ELA_ASSERT_INT_EQ(10, (int)ubi);
	ELA_ASSERT_INT_EQ(3, (int)vol);
}

static void test_ubi_ubiblock_with_path(void)
{
	unsigned int ubi = 0, vol = 0;

	ELA_ASSERT_INT_EQ(0, uboot_get_ubi_indices("/dev/ubiblock10_3", &ubi, &vol));
	ELA_ASSERT_INT_EQ(10, (int)ubi);
	ELA_ASSERT_INT_EQ(3, (int)vol);
}

static void test_ubi_single_device_no_vol_returns_minus1(void)
{
	unsigned int ubi = 0, vol = 0;

	/* "ubi4" without underscore is not a volume node */
	ELA_ASSERT_INT_EQ(-1, uboot_get_ubi_indices("/dev/ubi4", &ubi, &vol));
}

static void test_ubi_extra_chars_returns_minus1(void)
{
	unsigned int ubi = 0, vol = 0;

	ELA_ASSERT_INT_EQ(-1, uboot_get_ubi_indices("/dev/ubi4_1extra", &ubi, &vol));
}

static void test_ubi_non_ubi_prefix_returns_minus1(void)
{
	unsigned int ubi = 0, vol = 0;

	ELA_ASSERT_INT_EQ(-1, uboot_get_ubi_indices("/dev/mmcblk0", &ubi, &vol));
}

static void test_ubi_large_indices(void)
{
	unsigned int ubi = 0, vol = 0;

	ELA_ASSERT_INT_EQ(0, uboot_get_ubi_indices("ubi255_127", &ubi, &vol));
	ELA_ASSERT_INT_EQ(255, (int)ubi);
	ELA_ASSERT_INT_EQ(127, (int)vol);
}

/* =========================================================================
 * uboot_parse_major_minor
 * ====================================================================== */

static void test_major_minor_null_text_returns_minus1(void)
{
	unsigned int major = 0, minor = 0;

	ELA_ASSERT_INT_EQ(-1, uboot_parse_major_minor(NULL, &major, &minor));
}

static void test_major_minor_null_major_out_returns_minus1(void)
{
	unsigned int minor = 0;

	ELA_ASSERT_INT_EQ(-1, uboot_parse_major_minor("8:0", NULL, &minor));
}

static void test_major_minor_null_minor_out_returns_minus1(void)
{
	unsigned int major = 0;

	ELA_ASSERT_INT_EQ(-1, uboot_parse_major_minor("8:0", &major, NULL));
}

static void test_major_minor_simple_pair(void)
{
	unsigned int major = 0, minor = 0;

	ELA_ASSERT_INT_EQ(0, uboot_parse_major_minor("8:0", &major, &minor));
	ELA_ASSERT_INT_EQ(8, (int)major);
	ELA_ASSERT_INT_EQ(0, (int)minor);
}

static void test_major_minor_with_trailing_newline(void)
{
	unsigned int major = 0, minor = 0;

	ELA_ASSERT_INT_EQ(0, uboot_parse_major_minor("31:7\n", &major, &minor));
	ELA_ASSERT_INT_EQ(31, (int)major);
	ELA_ASSERT_INT_EQ(7, (int)minor);
}

static void test_major_minor_trailing_whitespace_ok(void)
{
	unsigned int major = 0, minor = 0;

	ELA_ASSERT_INT_EQ(0, uboot_parse_major_minor("10:5  \t\n", &major, &minor));
	ELA_ASSERT_INT_EQ(10, (int)major);
	ELA_ASSERT_INT_EQ(5, (int)minor);
}

static void test_major_minor_extra_text_returns_minus1(void)
{
	unsigned int major = 0, minor = 0;

	ELA_ASSERT_INT_EQ(-1, uboot_parse_major_minor("31:7 extra", &major, &minor));
}

static void test_major_minor_only_major_returns_minus1(void)
{
	unsigned int major = 0, minor = 0;

	ELA_ASSERT_INT_EQ(-1, uboot_parse_major_minor("31", &major, &minor));
}

static void test_major_minor_zero_zero(void)
{
	unsigned int major = 0xFF, minor = 0xFF;

	ELA_ASSERT_INT_EQ(0, uboot_parse_major_minor("0:0", &major, &minor));
	ELA_ASSERT_INT_EQ(0, (int)major);
	ELA_ASSERT_INT_EQ(0, (int)minor);
}

static void test_major_minor_large_values(void)
{
	unsigned int major = 0, minor = 0;

	ELA_ASSERT_INT_EQ(0, uboot_parse_major_minor("255:255", &major, &minor));
	ELA_ASSERT_INT_EQ(255, (int)major);
	ELA_ASSERT_INT_EQ(255, (int)minor);
}

/* =========================================================================
 * uboot_is_sd_block_name
 * ====================================================================== */

static void test_sd_null_returns_false(void)
{
	ELA_ASSERT_FALSE(uboot_is_sd_block_name(NULL));
}

static void test_sd_empty_returns_false(void)
{
	ELA_ASSERT_FALSE(uboot_is_sd_block_name(""));
}

static void test_sd_just_s_returns_false(void)
{
	ELA_ASSERT_FALSE(uboot_is_sd_block_name("s"));
}

static void test_sd_just_sd_returns_false(void)
{
	ELA_ASSERT_FALSE(uboot_is_sd_block_name("sd"));
}

static void test_sd_sda_returns_true(void)
{
	ELA_ASSERT_TRUE(uboot_is_sd_block_name("sda"));
}

static void test_sd_sdz_returns_true(void)
{
	ELA_ASSERT_TRUE(uboot_is_sd_block_name("sdz"));
}

static void test_sd_with_digits_returns_true(void)
{
	ELA_ASSERT_TRUE(uboot_is_sd_block_name("sda1"));
	ELA_ASSERT_TRUE(uboot_is_sd_block_name("sda12"));
}

static void test_sd_uppercase_letter_returns_false(void)
{
	ELA_ASSERT_FALSE(uboot_is_sd_block_name("sdA"));
	ELA_ASSERT_FALSE(uboot_is_sd_block_name("sdA1"));
}

static void test_sd_double_letter_returns_false(void)
{
	/* "sdaa" has two lowercase letters after "sd" — second is not a digit */
	ELA_ASSERT_FALSE(uboot_is_sd_block_name("sdaa"));
}

static void test_sd_nonnumeric_suffix_returns_false(void)
{
	/* "sdap" — 'p' is not a digit */
	ELA_ASSERT_FALSE(uboot_is_sd_block_name("sdap"));
}

/* =========================================================================
 * uboot_is_emmc_block_name
 * ====================================================================== */

static void test_emmc_null_returns_false(void)
{
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name(NULL));
}

static void test_emmc_empty_returns_false(void)
{
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name(""));
}

static void test_emmc_prefix_only_returns_false(void)
{
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name("mmcblk"));
}

static void test_emmc_mmcblk0_returns_true(void)
{
	ELA_ASSERT_TRUE(uboot_is_emmc_block_name("mmcblk0"));
}

static void test_emmc_mmcblk12_returns_true(void)
{
	ELA_ASSERT_TRUE(uboot_is_emmc_block_name("mmcblk12"));
}

static void test_emmc_mmcblk12p3_returns_true(void)
{
	ELA_ASSERT_TRUE(uboot_is_emmc_block_name("mmcblk12p3"));
}

static void test_emmc_mmcblk0p10_returns_true(void)
{
	ELA_ASSERT_TRUE(uboot_is_emmc_block_name("mmcblk0p10"));
}

static void test_emmc_p_with_no_digits_returns_false(void)
{
	/* "mmcblk0p" — 'p' present but no partition number follows */
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name("mmcblk0p"));
}

static void test_emmc_p_with_nonnumeric_returns_false(void)
{
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name("mmcblk0px"));
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name("mmcblk0pA"));
}

static void test_emmc_wrong_prefix_returns_false(void)
{
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name("sda"));
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name("mmcblX0"));
}

/* =========================================================================
 * uboot_free_created_nodes
 * ====================================================================== */

static void test_free_null_nodes_no_crash(void)
{
	/* Must not crash when nodes is NULL */
	uboot_free_created_nodes(NULL, 0);
	ELA_ASSERT_TRUE(1);
}

static void test_free_heap_allocated_nodes(void)
{
	char **nodes;
	size_t i;

	/* Build a small heap-allocated list the same way add_created_node would */
	nodes = malloc(3 * sizeof(char *));
	ELA_ASSERT_TRUE(nodes != NULL);
	nodes[0] = strdup("/dev/mtdblock0");
	nodes[1] = strdup("/dev/mtdblock1");
	nodes[2] = strdup("/dev/mtdblock2");
	ELA_ASSERT_TRUE(nodes[0] != NULL);
	ELA_ASSERT_TRUE(nodes[1] != NULL);
	ELA_ASSERT_TRUE(nodes[2] != NULL);

	/* If this crashes or trips ASan/valgrind the test fails */
	uboot_free_created_nodes(nodes, 3);

	/* nodes is freed; just verify we reached this point */
	ELA_ASSERT_TRUE(1);

	(void)i;
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_device_scan_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* ela_read_be32 */
		{ "be32/known_value",                   test_be32_known_value },
		{ "be32/all_zeros",                     test_be32_all_zeros },
		{ "be32/all_ff",                        test_be32_all_ff },
		{ "be32/incremental",                   test_be32_incremental },
		{ "be32/high_bit_only",                 test_be32_high_bit_only },
		{ "be32/low_byte_only",                 test_be32_low_byte_only },
		/* uboot_get_mtd_index */
		{ "mtd_index/null_idx",                 test_mtd_index_null_idx_returns_minus1 },
		{ "mtd_index/small_buf",                test_mtd_index_small_buf_returns_minus1 },
		{ "mtd_index/single_digit",             test_mtd_index_single_digit },
		{ "mtd_index/two_digits",               test_mtd_index_two_digits },
		{ "mtd_index/zero",                     test_mtd_index_zero },
		{ "mtd_index/mtdblock",                 test_mtd_index_mtdblock },
		{ "mtd_index/mtdblock_single",          test_mtd_index_mtdblock_single_digit },
		{ "mtd_index/ro_suffix",                test_mtd_index_ro_suffix_accepted },
		{ "mtd_index/no_path_sep",              test_mtd_index_no_path_separator },
		{ "mtd_index/no_digits",                test_mtd_index_no_digits_returns_minus1 },
		{ "mtd_index/mtdro_no_digits",          test_mtd_index_mtdro_no_digits_returns_minus1 },
		{ "mtd_index/extra_suffix",             test_mtd_index_extra_suffix_returns_minus1 },
		{ "mtd_index/non_mtd_prefix",           test_mtd_index_non_mtd_prefix_returns_minus1 },
		{ "mtd_index/mtdblock_no_digits",       test_mtd_index_mtdblock_no_digits_returns_minus1 },
		/* uboot_get_ubi_indices */
		{ "ubi_indices/null_ubi_out",           test_ubi_null_ubi_out_returns_minus1 },
		{ "ubi_indices/null_vol_out",           test_ubi_null_vol_out_returns_minus1 },
		{ "ubi_indices/simple_path",            test_ubi_simple_path },
		{ "ubi_indices/zero_zero",              test_ubi_zero_zero },
		{ "ubi_indices/ubiblock_no_path",       test_ubi_ubiblock_no_path },
		{ "ubi_indices/ubiblock_with_path",     test_ubi_ubiblock_with_path },
		{ "ubi_indices/single_no_vol",          test_ubi_single_device_no_vol_returns_minus1 },
		{ "ubi_indices/extra_chars",            test_ubi_extra_chars_returns_minus1 },
		{ "ubi_indices/non_ubi_prefix",         test_ubi_non_ubi_prefix_returns_minus1 },
		{ "ubi_indices/large_indices",          test_ubi_large_indices },
		/* uboot_parse_major_minor */
		{ "major_minor/null_text",              test_major_minor_null_text_returns_minus1 },
		{ "major_minor/null_major_out",         test_major_minor_null_major_out_returns_minus1 },
		{ "major_minor/null_minor_out",         test_major_minor_null_minor_out_returns_minus1 },
		{ "major_minor/simple",                 test_major_minor_simple_pair },
		{ "major_minor/trailing_newline",       test_major_minor_with_trailing_newline },
		{ "major_minor/trailing_whitespace",    test_major_minor_trailing_whitespace_ok },
		{ "major_minor/extra_text",             test_major_minor_extra_text_returns_minus1 },
		{ "major_minor/only_major",             test_major_minor_only_major_returns_minus1 },
		{ "major_minor/zero_zero",              test_major_minor_zero_zero },
		{ "major_minor/large_values",           test_major_minor_large_values },
		/* uboot_is_sd_block_name */
		{ "sd_name/null",                       test_sd_null_returns_false },
		{ "sd_name/empty",                      test_sd_empty_returns_false },
		{ "sd_name/just_s",                     test_sd_just_s_returns_false },
		{ "sd_name/just_sd",                    test_sd_just_sd_returns_false },
		{ "sd_name/sda",                        test_sd_sda_returns_true },
		{ "sd_name/sdz",                        test_sd_sdz_returns_true },
		{ "sd_name/with_digits",                test_sd_with_digits_returns_true },
		{ "sd_name/uppercase_letter",           test_sd_uppercase_letter_returns_false },
		{ "sd_name/double_letter",              test_sd_double_letter_returns_false },
		{ "sd_name/nonnumeric_suffix",          test_sd_nonnumeric_suffix_returns_false },
		/* uboot_is_emmc_block_name */
		{ "emmc_name/null",                     test_emmc_null_returns_false },
		{ "emmc_name/empty",                    test_emmc_empty_returns_false },
		{ "emmc_name/prefix_only",              test_emmc_prefix_only_returns_false },
		{ "emmc_name/mmcblk0",                  test_emmc_mmcblk0_returns_true },
		{ "emmc_name/mmcblk12",                 test_emmc_mmcblk12_returns_true },
		{ "emmc_name/mmcblk12p3",               test_emmc_mmcblk12p3_returns_true },
		{ "emmc_name/mmcblk0p10",               test_emmc_mmcblk0p10_returns_true },
		{ "emmc_name/p_no_digits",              test_emmc_p_with_no_digits_returns_false },
		{ "emmc_name/p_nonnumeric",             test_emmc_p_with_nonnumeric_returns_false },
		{ "emmc_name/wrong_prefix",             test_emmc_wrong_prefix_returns_false },
		/* uboot_free_created_nodes */
		{ "free_nodes/null_no_crash",           test_free_null_nodes_no_crash },
		{ "free_nodes/heap_allocated",          test_free_heap_allocated_nodes },
	};

	return ela_run_test_suite("device_scan", cases, sizeof(cases) / sizeof(cases[0]));
}
