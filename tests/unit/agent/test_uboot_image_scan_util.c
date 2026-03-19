// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/image/uboot_image_scan_util.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

#include <stdint.h>
#include <string.h>

/* =========================================================================
 * Blob-building helpers
 * ====================================================================== */

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)((v >> 24) & 0xff);
	p[1] = (uint8_t)((v >> 16) & 0xff);
	p[2] = (uint8_t)((v >>  8) & 0xff);
	p[3] = (uint8_t)(v & 0xff);
}

/*
 * Fill a 40-byte buffer with a FIT header.  Only the fields relevant to
 * ela_uboot_image_validate_fit_header are written; the magic bytes at [0-3]
 * are not checked by that function so they are zeroed.
 */
static void make_fit_hdr(uint8_t *h,
			 uint32_t totalsize,
			 uint32_t off_dt_struct,
			 uint32_t off_dt_strings,
			 uint32_t off_mem_rsvmap,
			 uint32_t version,
			 uint32_t last_comp_ver,
			 uint32_t size_dt_strings,
			 uint32_t size_dt_struct)
{
	memset(h, 0, 40);
	put_be32(h +  4, totalsize);
	put_be32(h +  8, off_dt_struct);
	put_be32(h + 12, off_dt_strings);
	put_be32(h + 16, off_mem_rsvmap);
	put_be32(h + 20, version);
	put_be32(h + 24, last_comp_ver);
	put_be32(h + 32, size_dt_strings);
	put_be32(h + 36, size_dt_struct);
}

/* Build a valid minimal FIT header with sane defaults. */
static void make_valid_fit_hdr(uint8_t *h)
{
	/* totalsize=0x200, struct at 0x80 size 0x80, strings at 0x100 size 0x80 */
	make_fit_hdr(h, 0x200, 0x80, 0x100, 0x50, 17, 16, 0x80, 0x80);
}

/*
 * Fill a 64-byte uImage header with a valid CRC.  data_size is written at
 * offset 12.  Bytes [4-7] receive the computed CRC32.
 */
static void make_uimage_hdr(uint8_t h[64], const uint32_t *crc_table,
			    uint32_t data_size)
{
	memset(h, 0, 64);
	h[0] = 0x27; h[1] = 0x05; h[2] = 0x19; h[3] = 0x56; /* uimage magic */
	put_be32(h + 12, data_size);
	put_be32(h + 4, ela_crc32_calc(crc_table, h, 64));
}

/*
 * Build an 80-byte FDT blob whose struct section contains a single "load"
 * property at the root level.
 *
 * Layout:
 *   [0..39]  : FDT header  (off_dt_struct=40, size_dt_struct=32,
 *                            off_dt_strings=72, size_dt_strings=5)
 *   [40..47] : FDT_BEGIN_NODE + "" + padding
 *   [48..51] : FDT_PROP token
 *   [52..55] : len=4
 *   [56..59] : nameoff=0
 *   [60..63] : load address (big-endian)
 *   [64..67] : FDT_END_NODE
 *   [68..71] : FDT_END
 *   [72..76] : "load\0"
 *   [77..79] : padding
 */
static void make_load_fdt_blob(uint8_t *blob, size_t blob_len, uint32_t load_addr)
{
	memset(blob, 0, blob_len);
	/* header */
	put_be32(blob +  4, 0x50);  /* totalsize = 80 */
	put_be32(blob +  8, 40);    /* off_dt_struct */
	put_be32(blob + 12, 72);    /* off_dt_strings */
	put_be32(blob + 32, 5);     /* size_dt_strings ("load\0") */
	put_be32(blob + 36, 32);    /* size_dt_struct */
	/* struct section */
	put_be32(blob + 40, 1);     /* FDT_BEGIN_NODE */
	/* blob[44] = 0x00 (empty name), blob[45-47] = padding */
	put_be32(blob + 48, 3);     /* FDT_PROP */
	put_be32(blob + 52, 4);     /* len = 4 */
	put_be32(blob + 56, 0);     /* nameoff = 0 ("load") */
	put_be32(blob + 60, load_addr);
	put_be32(blob + 64, 2);     /* FDT_END_NODE */
	put_be32(blob + 68, 9);     /* FDT_END */
	/* strings section */
	blob[72] = 'l'; blob[73] = 'o'; blob[74] = 'a';
	blob[75] = 'd'; blob[76] = '\0';
}

/* FDT blob with no "load" property: just BEGIN_NODE + END_NODE + END. */
static void make_no_load_fdt_blob(uint8_t *blob, size_t blob_len)
{
	memset(blob, 0, blob_len);
	put_be32(blob +  4, 64);   /* totalsize */
	put_be32(blob +  8, 40);   /* off_dt_struct */
	put_be32(blob + 12, 56);   /* off_dt_strings */
	put_be32(blob + 32, 1);    /* size_dt_strings (single NUL) */
	put_be32(blob + 36, 16);   /* size_dt_struct */
	put_be32(blob + 40, 1);    /* FDT_BEGIN_NODE */
	/* blob[44] = 0x00 (name), [45-47] = padding */
	put_be32(blob + 48, 2);    /* FDT_END_NODE */
	put_be32(blob + 52, 9);    /* FDT_END */
	/* strings: single NUL at blob[56] */
}

/* =========================================================================
 * ela_uboot_image_validate_fit_header
 * ====================================================================== */

static void test_fit_valid(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	ELA_ASSERT_TRUE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_totalsize_too_small(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	put_be32(h + 4, 0x0f); /* below FIT_MIN_TOTAL_SIZE (0x100) */
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_totalsize_too_large(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	put_be32(h + 4, 0x04000001); /* above FIT_MAX_TOTAL_SIZE (64 MiB) */
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000000));
}

static void test_fit_abs_off_plus_size_exceeds_dev(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h); /* totalsize=0x200 */
	/* abs_off=0x100, dev_size=0x200 → 0x100+0x200=0x300 > 0x200 */
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0x100, 0x200));
}

static void test_fit_mem_rsvmap_below_40(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	put_be32(h + 16, 20); /* off_mem_rsvmap < 40 */
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_mem_rsvmap_ge_totalsize(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	put_be32(h + 16, 0x200); /* == totalsize */
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_dt_struct_ge_totalsize(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	put_be32(h + 8, 0x200); /* off_dt_struct == totalsize */
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_dt_strings_ge_totalsize(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	put_be32(h + 12, 0x200); /* off_dt_strings == totalsize */
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_size_dt_struct_zero(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	put_be32(h + 36, 0);
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_size_dt_strings_zero(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	put_be32(h + 32, 0);
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_struct_overflows_totalsize(void)
{
	uint8_t h[40];
	/* off_dt_struct=0x1c0, size_dt_struct=0x80 → 0x240 > 0x200 */
	make_fit_hdr(h, 0x200, 0x1c0, 0x100, 0x50, 17, 16, 0x20, 0x80);
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_strings_overflows_totalsize(void)
{
	uint8_t h[40];
	/* off_dt_strings=0x1e0, size_dt_strings=0x80 → 0x260 > 0x200 */
	make_fit_hdr(h, 0x200, 0x80, 0x1e0, 0x50, 17, 16, 0x80, 0x80);
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_version_below_16(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	put_be32(h + 20, 15);
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_version_above_17(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	put_be32(h + 20, 18);
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

static void test_fit_last_comp_version_gt_version(void)
{
	uint8_t h[40];
	make_valid_fit_hdr(h);
	put_be32(h + 20, 16);
	put_be32(h + 24, 17); /* last_comp_version > version */
	ELA_ASSERT_FALSE(ela_uboot_image_validate_fit_header(h, 0, 0x10000));
}

/* =========================================================================
 * ela_uboot_image_validate_uimage_header
 * ====================================================================== */

static void test_uimage_valid(void)
{
	uint32_t tbl[256];
	uint8_t h[64];
	ela_crc32_init(tbl);
	make_uimage_hdr(h, tbl, 0x10000);
	ELA_ASSERT_TRUE(ela_uboot_image_validate_uimage_header(h, 0, 0x20000, tbl));
}

static void test_uimage_crc_mismatch(void)
{
	uint32_t tbl[256];
	uint8_t h[64];
	ela_crc32_init(tbl);
	memset(h, 0, sizeof(h));
	h[0] = 0x27; h[1] = 0x05; h[2] = 0x19; h[3] = 0x56;
	put_be32(h + 12, 0x1000);
	/* CRC at [4-7] is 0 — won't match computed CRC */
	ELA_ASSERT_FALSE(ela_uboot_image_validate_uimage_header(h, 0, 0x10000, tbl));
}

static void test_uimage_data_size_zero(void)
{
	uint32_t tbl[256];
	uint8_t h[64];
	ela_crc32_init(tbl);
	make_uimage_hdr(h, tbl, 0);
	ELA_ASSERT_FALSE(ela_uboot_image_validate_uimage_header(h, 0, 0x10000, tbl));
}

static void test_uimage_data_size_over_limit(void)
{
	uint32_t tbl[256];
	uint8_t h[64];
	ela_crc32_init(tbl);
	/* UIMAGE_MAX_DATA_SIZE = 256 MiB; use 256 MiB + 1 */
	make_uimage_hdr(h, tbl, (256U * 1024U * 1024U) + 1U);
	ELA_ASSERT_FALSE(ela_uboot_image_validate_uimage_header(
		h, 0, 0x100000000ULL, tbl));
}

static void test_uimage_exceeds_dev_size(void)
{
	uint32_t tbl[256];
	uint8_t h[64];
	ela_crc32_init(tbl);
	/* data_size=0x8000; abs_off=0, dev_size=64+0x8000-1 → just short */
	make_uimage_hdr(h, tbl, 0x8000);
	ELA_ASSERT_FALSE(ela_uboot_image_validate_uimage_header(
		h, 0, 64 + 0x8000 - 1, tbl));
}

/* =========================================================================
 * ela_uboot_image_fit_find_load_address
 * ====================================================================== */

static void test_fdt_null_blob(void)
{
	uint32_t addr = 0;
	ELA_ASSERT_FALSE(ela_uboot_image_fit_find_load_address(
		NULL, 80, &addr, NULL, NULL));
}

static void test_fdt_blob_size_too_small(void)
{
	uint8_t blob[80];
	uint32_t addr = 0;
	make_load_fdt_blob(blob, sizeof(blob), 0x80000000U);
	ELA_ASSERT_FALSE(ela_uboot_image_fit_find_load_address(
		blob, 39, &addr, NULL, NULL));
}

static void test_fdt_null_addr_out(void)
{
	uint8_t blob[80];
	make_load_fdt_blob(blob, sizeof(blob), 0x80000000U);
	ELA_ASSERT_FALSE(ela_uboot_image_fit_find_load_address(
		blob, sizeof(blob), NULL, NULL, NULL));
}

static void test_fdt_struct_bounds_exceeded(void)
{
	uint8_t blob[80];
	uint32_t addr = 0;
	make_load_fdt_blob(blob, sizeof(blob), 0x80000000U);
	/* off_dt_struct(40) + size_dt_struct(32) = 72; set blob_size=70 */
	ELA_ASSERT_FALSE(ela_uboot_image_fit_find_load_address(
		blob, 70, &addr, NULL, NULL));
}

static void test_fdt_strings_bounds_exceeded(void)
{
	uint8_t blob[80];
	uint32_t addr = 0;
	make_load_fdt_blob(blob, sizeof(blob), 0x80000000U);
	/* off_dt_strings(72) + size_dt_strings(5) = 77; set blob_size=75 */
	ELA_ASSERT_FALSE(ela_uboot_image_fit_find_load_address(
		blob, 75, &addr, NULL, NULL));
}

static void test_fdt_load_found(void)
{
	uint8_t blob[80];
	uint32_t addr = 0;
	make_load_fdt_blob(blob, sizeof(blob), 0x80000000U);
	ELA_ASSERT_TRUE(ela_uboot_image_fit_find_load_address(
		blob, sizeof(blob), &addr, NULL, NULL));
	ELA_ASSERT_INT_EQ(0x80000000U, (unsigned long)addr);
}

static void test_fdt_load_found_different_address(void)
{
	uint8_t blob[80];
	uint32_t addr = 0;
	make_load_fdt_blob(blob, sizeof(blob), 0x40080000U);
	ELA_ASSERT_TRUE(ela_uboot_image_fit_find_load_address(
		blob, sizeof(blob), &addr, NULL, NULL));
	ELA_ASSERT_INT_EQ(0x40080000U, (unsigned long)addr);
}

static void test_fdt_no_load_property(void)
{
	uint8_t blob[64];
	uint32_t addr = 0xdeadbeef;
	make_no_load_fdt_blob(blob, sizeof(blob));
	ELA_ASSERT_FALSE(ela_uboot_image_fit_find_load_address(
		blob, sizeof(blob), &addr, NULL, NULL));
}

static void test_fdt_uboot_off_out_null_safe(void)
{
	uint8_t blob[80];
	uint32_t addr = 0;
	make_load_fdt_blob(blob, sizeof(blob), 0x80000000U);
	/* passing NULL for uboot_off_out and uboot_off_found_out must not crash */
	ELA_ASSERT_TRUE(ela_uboot_image_fit_find_load_address(
		blob, sizeof(blob), &addr, NULL, NULL));
}

static void test_fdt_uboot_off_not_found_by_default(void)
{
	uint8_t blob[80];
	uint32_t addr = 0;
	uint64_t off = 0xdeadbeef;
	bool found = true;
	make_load_fdt_blob(blob, sizeof(blob), 0x80000000U);
	/* blob has no "images" node, so uboot_off should not be found */
	ela_uboot_image_fit_find_load_address(blob, sizeof(blob), &addr, &off, &found);
	ELA_ASSERT_FALSE(found);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_image_scan_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* validate_fit_header */
		{ "fit/valid",                         test_fit_valid },
		{ "fit/totalsize_too_small",           test_fit_totalsize_too_small },
		{ "fit/totalsize_too_large",           test_fit_totalsize_too_large },
		{ "fit/abs_off_exceeds_dev",           test_fit_abs_off_plus_size_exceeds_dev },
		{ "fit/mem_rsvmap_below_40",           test_fit_mem_rsvmap_below_40 },
		{ "fit/mem_rsvmap_ge_totalsize",       test_fit_mem_rsvmap_ge_totalsize },
		{ "fit/dt_struct_ge_totalsize",        test_fit_dt_struct_ge_totalsize },
		{ "fit/dt_strings_ge_totalsize",       test_fit_dt_strings_ge_totalsize },
		{ "fit/size_dt_struct_zero",           test_fit_size_dt_struct_zero },
		{ "fit/size_dt_strings_zero",          test_fit_size_dt_strings_zero },
		{ "fit/struct_overflows_totalsize",    test_fit_struct_overflows_totalsize },
		{ "fit/strings_overflows_totalsize",   test_fit_strings_overflows_totalsize },
		{ "fit/version_below_16",              test_fit_version_below_16 },
		{ "fit/version_above_17",              test_fit_version_above_17 },
		{ "fit/last_comp_gt_version",          test_fit_last_comp_version_gt_version },
		/* validate_uimage_header */
		{ "uimage/valid",                      test_uimage_valid },
		{ "uimage/crc_mismatch",               test_uimage_crc_mismatch },
		{ "uimage/data_size_zero",             test_uimage_data_size_zero },
		{ "uimage/data_size_over_limit",       test_uimage_data_size_over_limit },
		{ "uimage/exceeds_dev_size",           test_uimage_exceeds_dev_size },
		/* fit_find_load_address */
		{ "fdt/null_blob",                     test_fdt_null_blob },
		{ "fdt/blob_size_too_small",           test_fdt_blob_size_too_small },
		{ "fdt/null_addr_out",                 test_fdt_null_addr_out },
		{ "fdt/struct_bounds_exceeded",        test_fdt_struct_bounds_exceeded },
		{ "fdt/strings_bounds_exceeded",       test_fdt_strings_bounds_exceeded },
		{ "fdt/load_found",                    test_fdt_load_found },
		{ "fdt/load_found_different_addr",     test_fdt_load_found_different_address },
		{ "fdt/no_load_property",              test_fdt_no_load_property },
		{ "fdt/uboot_off_null_safe",           test_fdt_uboot_off_out_null_safe },
		{ "fdt/uboot_off_not_found",           test_fdt_uboot_off_not_found_by_default },
	};
	return ela_run_test_suite("uboot_image_scan_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
