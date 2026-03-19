// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/image/uboot_image_find_address_util.h"

#include <stdint.h>
#include <string.h>

/* =========================================================================
 * ela_uboot_image_uimage_read_load_addr
 * ====================================================================== */

static void test_load_addr_all_zero(void)
{
	uint8_t hdr[64];
	memset(hdr, 0, sizeof(hdr));
	ELA_ASSERT_INT_EQ(0, (int)ela_uboot_image_uimage_read_load_addr(hdr));
}

static void test_load_addr_known_value(void)
{
	uint8_t hdr[64];
	memset(hdr, 0, sizeof(hdr));
	/* 0x80008000 stored big-endian at offset 16 */
	hdr[16] = 0x80; hdr[17] = 0x00; hdr[18] = 0x80; hdr[19] = 0x00;
	ELA_ASSERT_INT_EQ((int)0x80008000U,
			  (int)ela_uboot_image_uimage_read_load_addr(hdr));
}

static void test_load_addr_be_ordering(void)
{
	uint8_t hdr[64];
	memset(hdr, 0, sizeof(hdr));
	/* 0x12345678 stored big-endian */
	hdr[16] = 0x12; hdr[17] = 0x34; hdr[18] = 0x56; hdr[19] = 0x78;
	ELA_ASSERT_INT_EQ((int)0x12345678U,
			  (int)ela_uboot_image_uimage_read_load_addr(hdr));
}

static void test_load_addr_max_value(void)
{
	uint8_t hdr[64];
	memset(hdr, 0, sizeof(hdr));
	hdr[16] = 0xff; hdr[17] = 0xff; hdr[18] = 0xff; hdr[19] = 0xff;
	ELA_ASSERT_INT_EQ((int)0xffffffffU,
			  (int)ela_uboot_image_uimage_read_load_addr(hdr));
}

static void test_load_addr_ignores_surrounding_bytes(void)
{
	uint8_t hdr[64];
	memset(hdr, 0xff, sizeof(hdr)); /* fill with 0xff */
	hdr[16] = 0x40; hdr[17] = 0x08; hdr[18] = 0x00; hdr[19] = 0x00;
	/* surrounding bytes are 0xff but should not affect the result */
	ELA_ASSERT_INT_EQ((int)0x40080000U,
			  (int)ela_uboot_image_uimage_read_load_addr(hdr));
}

/* =========================================================================
 * ela_uboot_image_find_format_addr32
 * ====================================================================== */

static void test_addr32_null_buf(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_find_format_addr32(0, NULL, 16));
}

static void test_addr32_zero_buflen(void)
{
	char buf[16];
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_find_format_addr32(0, buf, 0));
}

static void test_addr32_zero_addr(void)
{
	char buf[16];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_find_format_addr32(0, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("0x00000000", buf);
}

static void test_addr32_known_value(void)
{
	char buf[16];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_find_format_addr32(0x80008000U, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("0x80008000", buf);
}

static void test_addr32_max_value(void)
{
	char buf[16];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_find_format_addr32(0xffffffffU, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("0xffffffff", buf);
}

static void test_addr32_exact_fit(void)
{
	/* "0x12345678" is 10 chars + NUL = 11 bytes */
	char buf[11];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_find_format_addr32(0x12345678U, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("0x12345678", buf);
}

static void test_addr32_truncated(void)
{
	char buf[5]; /* too small */
	ELA_ASSERT_INT_EQ(1, ela_uboot_image_find_format_addr32(0x12345678U, buf, sizeof(buf)));
}

/* =========================================================================
 * ela_uboot_image_find_format_offset
 * ====================================================================== */

static void test_offset_null_buf(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_find_format_offset(0, NULL, 16));
}

static void test_offset_zero_buflen(void)
{
	char buf[16];
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_find_format_offset(0, buf, 0));
}

static void test_offset_zero(void)
{
	char buf[16];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_find_format_offset(0, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("0x0", buf);
}

static void test_offset_small(void)
{
	char buf[16];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_find_format_offset(0x8000, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("0x8000", buf);
}

static void test_offset_32bit_value(void)
{
	char buf[16];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_find_format_offset(0xffffffffULL, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("0xffffffff", buf);
}

static void test_offset_truncated(void)
{
	char buf[4]; /* too small for "0x8000" */
	ELA_ASSERT_INT_EQ(1, ela_uboot_image_find_format_offset(0x8000, buf, sizeof(buf)));
}

static void test_offset_exact_fit(void)
{
	/* "0x8000" is 6 chars + NUL = 7 bytes */
	char buf[7];
	ELA_ASSERT_INT_EQ(0, ela_uboot_image_find_format_offset(0x8000, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("0x8000", buf);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_image_find_address_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* uimage_read_load_addr */
		{ "load_addr/all_zero",          test_load_addr_all_zero },
		{ "load_addr/known_value",        test_load_addr_known_value },
		{ "load_addr/be_ordering",        test_load_addr_be_ordering },
		{ "load_addr/max_value",          test_load_addr_max_value },
		{ "load_addr/ignores_surrounds",  test_load_addr_ignores_surrounding_bytes },
		/* format_addr32 */
		{ "addr32/null_buf",             test_addr32_null_buf },
		{ "addr32/zero_buflen",          test_addr32_zero_buflen },
		{ "addr32/zero_addr",            test_addr32_zero_addr },
		{ "addr32/known_value",          test_addr32_known_value },
		{ "addr32/max_value",            test_addr32_max_value },
		{ "addr32/exact_fit",            test_addr32_exact_fit },
		{ "addr32/truncated",            test_addr32_truncated },
		/* format_offset */
		{ "offset/null_buf",             test_offset_null_buf },
		{ "offset/zero_buflen",          test_offset_zero_buflen },
		{ "offset/zero",                 test_offset_zero },
		{ "offset/small",                test_offset_small },
		{ "offset/32bit_value",          test_offset_32bit_value },
		{ "offset/truncated",            test_offset_truncated },
		{ "offset/exact_fit",            test_offset_exact_fit },
	};
	return ela_run_test_suite("uboot_image_find_address_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
