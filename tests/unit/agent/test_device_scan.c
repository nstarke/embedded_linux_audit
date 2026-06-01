// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

#include <dirent.h>
#include <glob.h>
#include <stdint.h>
#include <stdio.h>
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

static void test_emmc_digit_then_non_p_returns_false(void)
{
	/* digits present but the trailing char after them is not 'p' */
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name("mmcblk0x"));
	ELA_ASSERT_FALSE(uboot_is_emmc_block_name("mmcblk12z"));
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
 * uboot_guess_size/erasesize_from_sysfs
 *
 * These read hard-coded /sys/class/mtd paths.  A non-MTD name makes
 * uboot_get_mtd_index() fail (early return); a valid-but-absent index makes
 * the index parse succeed but read_u64_from_file() hit its open()-failure
 * path.  Both return 0.
 * ====================================================================== */

static void test_guess_size_from_sysfs_non_mtd_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_size_from_sysfs("/dev/sda"));
}

static void test_guess_size_from_sysfs_absent_index_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_size_from_sysfs("/dev/mtd99999"));
}

static void test_guess_erasesize_from_sysfs_non_mtd_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_erasesize_from_sysfs("/dev/sda"));
}

static void test_guess_erasesize_from_sysfs_absent_index_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_erasesize_from_sysfs("/dev/mtd99999"));
}

/* =========================================================================
 * uboot_guess_size/erasesize_from_proc_mtd
 *
 * A non-MTD name makes make_proc_mtd_name() yield an empty string (early
 * return).  A valid MTD name with no matching /proc/mtd entry walks the file
 * (or fails to open it) and returns 0.
 * ====================================================================== */

static void test_guess_size_from_proc_mtd_non_mtd_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_size_from_proc_mtd("/dev/sda"));
}

static void test_guess_size_from_proc_mtd_absent_entry_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_size_from_proc_mtd("/dev/mtd99999"));
}

static void test_guess_erasesize_from_proc_mtd_non_mtd_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_erasesize_from_proc_mtd("/dev/sda"));
}

static void test_guess_erasesize_from_proc_mtd_absent_entry_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_erasesize_from_proc_mtd("/dev/mtd99999"));
}

/* =========================================================================
 * uboot_guess_size/step_from_ubi_sysfs
 *
 * A non-UBI name makes uboot_get_ubi_indices() fail (early return); valid
 * indices with absent attribute files walk every read_u64_from_file() lookup
 * and return 0.
 * ====================================================================== */

static void test_guess_size_from_ubi_sysfs_non_ubi_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_size_from_ubi_sysfs("/dev/sda"));
}

static void test_guess_size_from_ubi_sysfs_absent_attrs_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_size_from_ubi_sysfs("/dev/ubi99_99"));
}

static void test_guess_step_from_ubi_sysfs_non_ubi_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_step_from_ubi_sysfs("/dev/sda"));
}

static void test_guess_step_from_ubi_sysfs_absent_attrs_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_step_from_ubi_sysfs("/dev/ubi99_99"));
}

/* =========================================================================
 * uboot_guess_size/step_from_block_sysfs
 * ====================================================================== */

static void test_guess_size_from_block_sysfs_null_returns_zero(void)
{
	/* dev_basename(NULL) returns NULL -> early return */
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_size_from_block_sysfs(NULL));
}

static void test_guess_size_from_block_sysfs_empty_basename_returns_zero(void)
{
	/* trailing slash -> empty basename -> early return */
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_size_from_block_sysfs("/dev/"));
}

static void test_guess_size_from_block_sysfs_absent_returns_zero(void)
{
	/* nonexistent device -> /size absent -> sectors == 0 -> return 0 */
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_size_from_block_sysfs("/dev/zzznosuchdev0"));
}

static void test_guess_step_from_block_sysfs_null_returns_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_step_from_block_sysfs(NULL));
}

static void test_guess_step_from_block_sysfs_absent_returns_default_512(void)
{
	/* both io-size files absent -> documented 512-byte default */
	ELA_ASSERT_INT_EQ(512, (int)uboot_guess_step_from_block_sysfs("/dev/zzznosuchdev0"));
}

/*
 * If the host exposes any block device, exercise the success path of
 * read_u64_from_file() and the block-sysfs guessers against a real /size
 * attribute.  Pure smoke test: it must not crash, and the numeric result is
 * environment-dependent so it is not asserted.
 */
static void test_guess_block_sysfs_real_device_smoke(void)
{
	DIR *dir = opendir("/sys/class/block");
	struct dirent *de;

	if (!dir) {
		ELA_ASSERT_TRUE(1); /* no sysfs block class available */
		return;
	}

	while ((de = readdir(dir))) {
		char dev[sizeof("/dev/") + sizeof(de->d_name)];

		if (de->d_name[0] == '.')
			continue;

		snprintf(dev, sizeof(dev), "/dev/%s", de->d_name);
		(void)uboot_guess_size_from_block_sysfs(dev);
		(void)uboot_guess_step_from_block_sysfs(dev);
		(void)uboot_guess_size_any(dev);
		(void)uboot_guess_step_any(dev);
		break;
	}

	closedir(dir);
	ELA_ASSERT_TRUE(1);
}

/* =========================================================================
 * uboot_guess_size_any / uboot_guess_step_any
 * ====================================================================== */

static void test_guess_size_any_invalid_returns_zero(void)
{
	/* No MTD/proc/UBI/block source resolves -> 0 */
	ELA_ASSERT_INT_EQ(0, (int)uboot_guess_size_any("/dev/zzznosuchdev0"));
}

static void test_guess_step_any_invalid_returns_block_default_512(void)
{
	/*
	 * MTD/proc/UBI steps all resolve to 0, so the chain falls through to
	 * uboot_guess_step_from_block_sysfs(), which defaults to 512.
	 */
	ELA_ASSERT_INT_EQ(512, (int)uboot_guess_step_any("/dev/zzznosuchdev0"));
}

/* =========================================================================
 * uboot_glob_scan_devices
 * ====================================================================== */

static void test_glob_scan_null_out_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, uboot_glob_scan_devices(NULL, FW_SCAN_GLOB_MTDBLOCK));
}

static void test_glob_scan_zero_flags_returns_zero(void)
{
	glob_t g;

	/* No patterns selected: the loop body never runs, result is empty. */
	ELA_ASSERT_INT_EQ(0, uboot_glob_scan_devices(&g, 0));
	globfree(&g);
}

static void test_glob_scan_each_flag(void)
{
	static const unsigned int flags[] = {
		FW_SCAN_GLOB_MTDBLOCK, FW_SCAN_GLOB_MTDCHAR,
		FW_SCAN_GLOB_UBI,      FW_SCAN_GLOB_UBIBLOCK,
		FW_SCAN_GLOB_MMCBLK,   FW_SCAN_GLOB_SDBLK,
	};
	size_t i;

	for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
		glob_t g;

		ELA_ASSERT_INT_EQ(0, uboot_glob_scan_devices(&g, flags[i]));
		globfree(&g);
	}
}

static void test_glob_scan_all_flags(void)
{
	glob_t g;
	unsigned int all = FW_SCAN_GLOB_MTDBLOCK | FW_SCAN_GLOB_MTDCHAR |
			   FW_SCAN_GLOB_UBI | FW_SCAN_GLOB_UBIBLOCK |
			   FW_SCAN_GLOB_MMCBLK | FW_SCAN_GLOB_SDBLK;

	/* Multiple patterns exercise the GLOB_APPEND (did_call) branch. */
	ELA_ASSERT_INT_EQ(0, uboot_glob_scan_devices(&g, all));
	globfree(&g);
}

/* =========================================================================
 * uboot_ensure_* node scanners
 *
 * Run as a non-root user, mknod() fails with EPERM and creates nothing, so
 * these are effectively read-only directory walks.  /sys/class/mtd and
 * /sys/class/ubi are usually absent on a build host (opendir fails -> -1),
 * while /sys/class/block exists (returns 0).  We only assert the return code
 * is sane and that the calls do not crash.
 * ====================================================================== */

static void test_ensure_mtd_nodes_collect_smoke(void)
{
	char **nodes = NULL;
	size_t count = 0;
	int rc = uboot_ensure_mtd_nodes_collect(false, &nodes, &count);

	ELA_ASSERT_TRUE(rc == 0 || rc == -1);
	uboot_free_created_nodes(nodes, count);
}

static void test_ensure_ubi_nodes_collect_smoke(void)
{
	char **nodes = NULL;
	size_t count = 0;
	int rc = uboot_ensure_ubi_nodes_collect(false, &nodes, &count);

	ELA_ASSERT_TRUE(rc == 0 || rc == -1);
	uboot_free_created_nodes(nodes, count);
}

static void test_ensure_block_nodes_collect_include_smoke(void)
{
	char **nodes = NULL;
	size_t count = 0;
	/* include_sd / include_emmc true exercises the name-match arms */
	int rc = uboot_ensure_block_nodes_collect(false, true, true, &nodes, &count);

	ELA_ASSERT_TRUE(rc == 0 || rc == -1);
	uboot_free_created_nodes(nodes, count);
}

static void test_ensure_block_nodes_collect_exclude_smoke(void)
{
	/* include flags false exercises the skip-continue arms */
	int rc = uboot_ensure_block_nodes_collect(false, false, false, NULL, NULL);

	ELA_ASSERT_TRUE(rc == 0 || rc == -1);
}

static void test_ensure_void_wrappers_smoke(void)
{
	uboot_ensure_mtd_nodes(false);
	uboot_ensure_ubi_nodes(false);
	uboot_ensure_block_nodes(false, false, false);
	ELA_ASSERT_TRUE(1);
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
		{ "emmc_name/digit_then_non_p",         test_emmc_digit_then_non_p_returns_false },
		/* uboot_free_created_nodes */
		{ "free_nodes/null_no_crash",           test_free_null_nodes_no_crash },
		{ "free_nodes/heap_allocated",          test_free_heap_allocated_nodes },
		/* uboot_guess_size/erasesize_from_sysfs */
		{ "guess/size_sysfs_non_mtd",           test_guess_size_from_sysfs_non_mtd_returns_zero },
		{ "guess/size_sysfs_absent_index",      test_guess_size_from_sysfs_absent_index_returns_zero },
		{ "guess/erasesize_sysfs_non_mtd",      test_guess_erasesize_from_sysfs_non_mtd_returns_zero },
		{ "guess/erasesize_sysfs_absent_index", test_guess_erasesize_from_sysfs_absent_index_returns_zero },
		/* uboot_guess_size/erasesize_from_proc_mtd */
		{ "guess/size_proc_mtd_non_mtd",        test_guess_size_from_proc_mtd_non_mtd_returns_zero },
		{ "guess/size_proc_mtd_absent",         test_guess_size_from_proc_mtd_absent_entry_returns_zero },
		{ "guess/erasesize_proc_mtd_non_mtd",   test_guess_erasesize_from_proc_mtd_non_mtd_returns_zero },
		{ "guess/erasesize_proc_mtd_absent",    test_guess_erasesize_from_proc_mtd_absent_entry_returns_zero },
		/* uboot_guess_size/step_from_ubi_sysfs */
		{ "guess/size_ubi_non_ubi",             test_guess_size_from_ubi_sysfs_non_ubi_returns_zero },
		{ "guess/size_ubi_absent_attrs",        test_guess_size_from_ubi_sysfs_absent_attrs_returns_zero },
		{ "guess/step_ubi_non_ubi",             test_guess_step_from_ubi_sysfs_non_ubi_returns_zero },
		{ "guess/step_ubi_absent_attrs",        test_guess_step_from_ubi_sysfs_absent_attrs_returns_zero },
		/* uboot_guess_size/step_from_block_sysfs */
		{ "guess/size_block_null",              test_guess_size_from_block_sysfs_null_returns_zero },
		{ "guess/size_block_empty_basename",    test_guess_size_from_block_sysfs_empty_basename_returns_zero },
		{ "guess/size_block_absent",            test_guess_size_from_block_sysfs_absent_returns_zero },
		{ "guess/step_block_null",              test_guess_step_from_block_sysfs_null_returns_zero },
		{ "guess/step_block_absent_default",    test_guess_step_from_block_sysfs_absent_returns_default_512 },
		{ "guess/block_real_device_smoke",      test_guess_block_sysfs_real_device_smoke },
		/* uboot_guess_size_any / uboot_guess_step_any */
		{ "guess/size_any_invalid",             test_guess_size_any_invalid_returns_zero },
		{ "guess/step_any_invalid_default",     test_guess_step_any_invalid_returns_block_default_512 },
		/* uboot_glob_scan_devices */
		{ "glob_scan/null_out",                 test_glob_scan_null_out_returns_minus1 },
		{ "glob_scan/zero_flags",               test_glob_scan_zero_flags_returns_zero },
		{ "glob_scan/each_flag",                test_glob_scan_each_flag },
		{ "glob_scan/all_flags",                test_glob_scan_all_flags },
		/* uboot_ensure_* node scanners */
		{ "ensure/mtd_collect_smoke",           test_ensure_mtd_nodes_collect_smoke },
		{ "ensure/ubi_collect_smoke",           test_ensure_ubi_nodes_collect_smoke },
		{ "ensure/block_collect_include_smoke", test_ensure_block_nodes_collect_include_smoke },
		{ "ensure/block_collect_exclude_smoke", test_ensure_block_nodes_collect_exclude_smoke },
		{ "ensure/void_wrappers_smoke",         test_ensure_void_wrappers_smoke },
	};

	return ela_run_test_suite("device_scan", cases, sizeof(cases) / sizeof(cases[0]));
}
