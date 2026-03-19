// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/image/uboot_image_pull_util.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

#include <stdint.h>
#include <string.h>

/* =========================================================================
 * Helpers shared with test_uboot_image_scan_util
 * ====================================================================== */

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)((v >> 24) & 0xff);
	p[1] = (uint8_t)((v >> 16) & 0xff);
	p[2] = (uint8_t)((v >>  8) & 0xff);
	p[3] = (uint8_t)(v & 0xff);
}

/*
 * Build a minimal valid uImage header (64 bytes) with the correct CRC
 * and the given data_size.
 */
static void make_uimage_hdr(uint8_t h[64], const uint32_t *crc_table,
			    uint32_t data_size)
{
	memset(h, 0, 64);
	h[0] = 0x27; h[1] = 0x05; h[2] = 0x19; h[3] = 0x56;
	put_be32(h + 12, data_size);
	put_be32(h + 4, ela_crc32_calc(crc_table, h, 64));
}

/*
 * Build a minimal valid FIT header (40 bytes).
 * totalsize=0x200, struct at 0x80 size 0x80, strings at 0x100 size 0x80.
 */
static void make_valid_fit_hdr(uint8_t *h)
{
	memset(h, 0, 40);
	put_be32(h +  4, 0x200);  /* totalsize */
	put_be32(h +  8, 0x80);   /* off_dt_struct */
	put_be32(h + 12, 0x100);  /* off_dt_strings */
	put_be32(h + 16, 0x50);   /* off_mem_rsvmap */
	put_be32(h + 20, 17);     /* version */
	put_be32(h + 24, 16);     /* last_comp_version */
	put_be32(h + 32, 0x80);   /* size_dt_strings */
	put_be32(h + 36, 0x80);   /* size_dt_struct */
}

/* =========================================================================
 * ela_uboot_image_pull_detect_size
 * ====================================================================== */

static void test_detect_null_hdr(void)
{
	uint32_t tbl[256];
	uint64_t sz = 0;
	ela_crc32_init(tbl);
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_pull_detect_size(
		NULL, 0, UINT64_MAX, tbl, &sz));
}

static void test_detect_null_crc_table(void)
{
	uint8_t hdr[64];
	uint64_t sz = 0;
	memset(hdr, 0, sizeof(hdr));
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_pull_detect_size(
		hdr, 0, UINT64_MAX, NULL, &sz));
}

static void test_detect_null_total_size_out(void)
{
	uint32_t tbl[256];
	uint8_t hdr[64];
	ela_crc32_init(tbl);
	memset(hdr, 0, sizeof(hdr));
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_pull_detect_size(
		hdr, 0, UINT64_MAX, tbl, NULL));
}

static void test_detect_unknown_magic(void)
{
	uint32_t tbl[256];
	uint8_t hdr[64];
	uint64_t sz = 0;
	ela_crc32_init(tbl);
	memset(hdr, 0, sizeof(hdr)); /* all-zero magic is unknown */
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_pull_detect_size(
		hdr, 0, UINT64_MAX, tbl, &sz));
}

static void test_detect_uimage_valid(void)
{
	uint32_t tbl[256];
	uint8_t hdr[64];
	uint64_t sz = 0;
	ela_crc32_init(tbl);
	make_uimage_hdr(hdr, tbl, 0x10000);
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_pull_detect_size(
		hdr, 0, 0x200000, tbl, &sz));
}

static void test_detect_uimage_total_size(void)
{
	uint32_t tbl[256];
	uint8_t hdr[64];
	uint64_t sz = 0;
	ela_crc32_init(tbl);
	make_uimage_hdr(hdr, tbl, 0x8000);
	ela_uboot_image_pull_detect_size(hdr, 0, 0x200000, tbl, &sz);
	/* total_size = UIMAGE_HDR_SIZE (64) + data_size */
	ELA_ASSERT_INT_EQ(64 + 0x8000, (unsigned long)sz);
}

static void test_detect_uimage_invalid_crc(void)
{
	uint32_t tbl[256];
	uint8_t hdr[64];
	uint64_t sz = 0;
	ela_crc32_init(tbl);
	memset(hdr, 0, sizeof(hdr));
	hdr[0] = 0x27; hdr[1] = 0x05; hdr[2] = 0x19; hdr[3] = 0x56;
	put_be32(hdr + 12, 0x1000); /* valid data_size */
	/* CRC at [4-7] left as 0 — won't match computed value */
	ELA_ASSERT_INT_EQ(-2, ela_uboot_image_pull_detect_size(
		hdr, 0, UINT64_MAX, tbl, &sz));
}

static void test_detect_uimage_zero_data_size(void)
{
	uint32_t tbl[256];
	uint8_t hdr[64];
	uint64_t sz = 0;
	ela_crc32_init(tbl);
	/* make_uimage_hdr with data_size=0: CRC passes but size check fails */
	make_uimage_hdr(hdr, tbl, 0);
	ELA_ASSERT_INT_EQ(-2, ela_uboot_image_pull_detect_size(
		hdr, 0, UINT64_MAX, tbl, &sz));
}

static void test_detect_fit_valid(void)
{
	uint32_t tbl[256];
	uint8_t hdr[40];
	uint64_t sz = 0;
	ela_crc32_init(tbl);
	make_valid_fit_hdr(hdr);
	hdr[0] = 0xD0; hdr[1] = 0x0D; hdr[2] = 0xFE; hdr[3] = 0xED;
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_pull_detect_size(
		hdr, 0, 0x10000, tbl, &sz));
}

static void test_detect_fit_total_size(void)
{
	uint32_t tbl[256];
	uint8_t hdr[40];
	uint64_t sz = 0;
	ela_crc32_init(tbl);
	make_valid_fit_hdr(hdr);
	hdr[0] = 0xD0; hdr[1] = 0x0D; hdr[2] = 0xFE; hdr[3] = 0xED;
	/* totalsize is at hdr+4 = 0x200 */
	ela_uboot_image_pull_detect_size(hdr, 0, 0x10000, tbl, &sz);
	ELA_ASSERT_INT_EQ(0x200, (unsigned long)sz);
}

static void test_detect_fit_invalid_header(void)
{
	uint32_t tbl[256];
	uint8_t hdr[40];
	uint64_t sz = 0;
	ela_crc32_init(tbl);
	memset(hdr, 0, sizeof(hdr));
	hdr[0] = 0xD0; hdr[1] = 0x0D; hdr[2] = 0xFE; hdr[3] = 0xED;
	/* totalsize=0 at hdr+4 → too small → validation fails */
	ELA_ASSERT_INT_EQ(-3, ela_uboot_image_pull_detect_size(
		hdr, 0, UINT64_MAX, tbl, &sz));
}

/* =========================================================================
 * ela_uboot_image_pull_build_file_path
 * ====================================================================== */

static void test_path_null_buf(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_pull_build_file_path(
		"/dev/mtd0", 0, NULL, 64));
}

static void test_path_zero_buflen(void)
{
	char buf[64];
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_pull_build_file_path(
		"/dev/mtd0", 0, buf, 0));
}

static void test_path_basic(void)
{
	char buf[64];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_pull_build_file_path(
		"/dev/mtd0", 0, buf, sizeof(buf)));
	ELA_ASSERT_INT_EQ(0, strcmp(buf, "/dev/mtd0@0x0.bin"));
}

static void test_path_nonzero_offset(void)
{
	char buf[64];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_pull_build_file_path(
		"/dev/mmcblk0", 0x8000, buf, sizeof(buf)));
	ELA_ASSERT_INT_EQ(0, strcmp(buf, "/dev/mmcblk0@0x8000.bin"));
}

static void test_path_large_offset(void)
{
	char buf[64];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_pull_build_file_path(
		"/dev/sda", 0xffffffff, buf, sizeof(buf)));
	ELA_ASSERT_INT_EQ(0, strcmp(buf, "/dev/sda@0xffffffff.bin"));
}

static void test_path_truncated(void)
{
	char buf[5]; /* too small for any real path */
	ELA_ASSERT_INT_EQ(1, ela_uboot_image_pull_build_file_path(
		"/dev/mtd0", 0, buf, sizeof(buf)));
}

static void test_path_exact_fit(void)
{
	/* "/dev/mtd0@0x0.bin" is 17 chars + NUL = 18 bytes */
	char buf[18];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_pull_build_file_path(
		"/dev/mtd0", 0, buf, sizeof(buf)));
	ELA_ASSERT_INT_EQ(0, strcmp(buf, "/dev/mtd0@0x0.bin"));
}

static void test_path_null_dev(void)
{
	char buf[32];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_pull_build_file_path(
		NULL, 0, buf, sizeof(buf)));
	ELA_ASSERT_INT_EQ(0, strcmp(buf, "@0x0.bin"));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_image_pull_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* detect_size — null guards */
		{ "detect/null_hdr",           test_detect_null_hdr },
		{ "detect/null_crc_table",     test_detect_null_crc_table },
		{ "detect/null_total_size",    test_detect_null_total_size_out },
		/* detect_size — unknown magic */
		{ "detect/unknown_magic",      test_detect_unknown_magic },
		/* detect_size — uImage */
		{ "detect/uimage_valid",       test_detect_uimage_valid },
		{ "detect/uimage_total_size",  test_detect_uimage_total_size },
		{ "detect/uimage_bad_crc",     test_detect_uimage_invalid_crc },
		{ "detect/uimage_zero_data",   test_detect_uimage_zero_data_size },
		/* detect_size — FIT */
		{ "detect/fit_valid",          test_detect_fit_valid },
		{ "detect/fit_total_size",     test_detect_fit_total_size },
		{ "detect/fit_invalid",        test_detect_fit_invalid_header },
		/* build_file_path */
		{ "path/null_buf",             test_path_null_buf },
		{ "path/zero_buflen",          test_path_zero_buflen },
		{ "path/basic",                test_path_basic },
		{ "path/nonzero_offset",       test_path_nonzero_offset },
		{ "path/large_offset",         test_path_large_offset },
		{ "path/truncated",            test_path_truncated },
		{ "path/exact_fit",            test_path_exact_fit },
		{ "path/null_dev",             test_path_null_dev },
	};
	return ela_run_test_suite("uboot_image_pull_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
