// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/env/uboot_env_util.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * ela_uboot_env_set_kv
 * ====================================================================== */

static void test_set_kv_null_inputs(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_set_kv(NULL, &count, "k", "v"));
	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_set_kv(&kvs, NULL, "k", "v"));
	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_set_kv(&kvs, &count, NULL, "v"));
	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_set_kv(&kvs, &count, "k", NULL));
	ELA_ASSERT_INT_EQ(0, count);
}

static void test_set_kv_adds_new_entry(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "bootcmd", "run boot"));
	ELA_ASSERT_INT_EQ(1, count);
	ELA_ASSERT_STR_EQ("bootcmd", kvs[0].name);
	ELA_ASSERT_STR_EQ("run boot", kvs[0].value);
	ela_uboot_env_free_kvs(kvs, count);
}

static void test_set_kv_update_existing(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "bootdelay", "3"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "bootdelay", "5"));
	ELA_ASSERT_INT_EQ(1, count);
	ELA_ASSERT_STR_EQ("5", kvs[0].value);
	ela_uboot_env_free_kvs(kvs, count);
}

static void test_set_kv_multiple_distinct_keys(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "a", "1"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "b", "2"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "c", "3"));
	ELA_ASSERT_INT_EQ(3, count);
	ela_uboot_env_free_kvs(kvs, count);
}

/* =========================================================================
 * ela_uboot_env_unset_kv
 * ====================================================================== */

static void test_unset_kv_null_inputs(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_unset_kv(NULL, &count, "k"));
	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_unset_kv(kvs, NULL, "k"));
	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_unset_kv(kvs, &count, NULL));
}

static void test_unset_kv_nonexistent_is_ok(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "k", "v"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_unset_kv(kvs, &count, "nothere"));
	ELA_ASSERT_INT_EQ(1, count);
	ela_uboot_env_free_kvs(kvs, count);
}

static void test_unset_kv_removes_only_element(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "x", "1"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_unset_kv(kvs, &count, "x"));
	ELA_ASSERT_INT_EQ(0, count);
	ela_uboot_env_free_kvs(kvs, count);
}

static void test_unset_kv_middle_element_shifts(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "a", "1"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "b", "2"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "c", "3"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_unset_kv(kvs, &count, "b"));
	ELA_ASSERT_INT_EQ(2, count);
	ELA_ASSERT_STR_EQ("a", kvs[0].name);
	ELA_ASSERT_STR_EQ("c", kvs[1].name);
	ela_uboot_env_free_kvs(kvs, count);
}

/* =========================================================================
 * ela_uboot_parse_fw_config_line
 * ====================================================================== */

static void test_parse_fw_config_line_null(void)
{
	struct uboot_cfg_entry cfg;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_parse_fw_config_line(NULL, &cfg));
}

static void test_parse_fw_config_line_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_parse_fw_config_line("/dev/mtd0 0x0 0x2000 0x2000 1", NULL));
}

static void test_parse_fw_config_line_blank(void)
{
	struct uboot_cfg_entry cfg;

	ELA_ASSERT_INT_EQ(0, ela_uboot_parse_fw_config_line("", &cfg));
	ELA_ASSERT_INT_EQ(0, ela_uboot_parse_fw_config_line("   ", &cfg));
}

static void test_parse_fw_config_line_comment(void)
{
	struct uboot_cfg_entry cfg;

	ELA_ASSERT_INT_EQ(0, ela_uboot_parse_fw_config_line("# /dev/mtd0 0x0 0x2000 0x2000 1", &cfg));
}

static void test_parse_fw_config_line_too_few_fields(void)
{
	struct uboot_cfg_entry cfg;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_parse_fw_config_line("/dev/mtd0 0x0 0x2000", &cfg));
}

static void test_parse_fw_config_line_invalid_offset(void)
{
	struct uboot_cfg_entry cfg;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_parse_fw_config_line("/dev/mtd0 notanumber 0x2000 0x2000 1", &cfg));
}

static void test_parse_fw_config_line_zero_env_size(void)
{
	struct uboot_cfg_entry cfg;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_parse_fw_config_line("/dev/mtd0 0x0 0x0 0x2000 1", &cfg));
}

static void test_parse_fw_config_line_too_small_env_size(void)
{
	struct uboot_cfg_entry cfg;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_parse_fw_config_line("/dev/mtd0 0x0 0x7 0x2000 1", &cfg));
}

static void test_parse_fw_config_line_valid_parses_fields(void)
{
	struct uboot_cfg_entry cfg;

	ELA_ASSERT_INT_EQ(1, ela_uboot_parse_fw_config_line("/dev/mtd0 0x0 0x2000 0x2000 1", &cfg));
	ELA_ASSERT_STR_EQ("/dev/mtd0", cfg.dev);
	ELA_ASSERT_INT_EQ(0, cfg.off);
	ELA_ASSERT_INT_EQ(0x2000, cfg.env_size);
	ELA_ASSERT_INT_EQ(0x2000, cfg.erase_size);
	ELA_ASSERT_INT_EQ(1, cfg.sectors);
}

static void test_parse_fw_config_line_nonzero_offset(void)
{
	struct uboot_cfg_entry cfg;

	ELA_ASSERT_INT_EQ(1, ela_uboot_parse_fw_config_line("/dev/mmcblk0 0x100000 0x4000 0x4000 2", &cfg));
	ELA_ASSERT_INT_EQ(0x100000, cfg.off);
	ELA_ASSERT_INT_EQ(0x4000, cfg.env_size);
}

static void test_parse_fw_config_line_leading_whitespace(void)
{
	struct uboot_cfg_entry cfg;

	ELA_ASSERT_INT_EQ(1, ela_uboot_parse_fw_config_line("  /dev/mtd1 0x0 0x2000 0x2000 1", &cfg));
	ELA_ASSERT_STR_EQ("/dev/mtd1", cfg.dev);
}

/* =========================================================================
 * ela_uboot_parse_existing_env_data
 * ====================================================================== */

static void test_parse_existing_env_data_null(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;
	static const uint8_t buf[] = "k=v\0\0";

	ELA_ASSERT_INT_EQ(-1, ela_uboot_parse_existing_env_data(NULL, 5, 0, &kvs, &count));
	ELA_ASSERT_INT_EQ(-1, ela_uboot_parse_existing_env_data(buf, 5, 0, NULL, &count));
	ELA_ASSERT_INT_EQ(-1, ela_uboot_parse_existing_env_data(buf, 5, 0, &kvs, NULL));
}

static void test_parse_existing_env_data_offset_past_end(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;
	static const uint8_t buf[] = "k=v\0\0";

	ELA_ASSERT_INT_EQ(-1, ela_uboot_parse_existing_env_data(buf, sizeof(buf) - 1, 10, &kvs, &count));
}

static void test_parse_existing_env_data_empty(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;
	static const uint8_t buf[] = "\0\0";

	ELA_ASSERT_INT_EQ(0, ela_uboot_parse_existing_env_data(buf, sizeof(buf) - 1, 0, &kvs, &count));
	ELA_ASSERT_INT_EQ(0, count);
}

static void test_parse_existing_env_data_no_eq_skipped(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;
	/* "noeq" has no '=' and should be skipped; "x=y" should be parsed */
	static const uint8_t buf[] = "noeq\0x=y\0\0";

	ELA_ASSERT_INT_EQ(0, ela_uboot_parse_existing_env_data(buf, sizeof(buf) - 1, 0, &kvs, &count));
	ELA_ASSERT_INT_EQ(1, count);
	ELA_ASSERT_STR_EQ("x", kvs[0].name);
	ELA_ASSERT_STR_EQ("y", kvs[0].value);
	ela_uboot_env_free_kvs(kvs, count);
}

static void test_parse_existing_env_data_two_pairs(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;
	static const uint8_t buf[] = "bootcmd=run boot\0bootdelay=3\0\0";

	ELA_ASSERT_INT_EQ(0, ela_uboot_parse_existing_env_data(buf, sizeof(buf) - 1, 0, &kvs, &count));
	ELA_ASSERT_INT_EQ(2, count);
	ELA_ASSERT_STR_EQ("bootcmd", kvs[0].name);
	ELA_ASSERT_STR_EQ("run boot", kvs[0].value);
	ELA_ASSERT_STR_EQ("bootdelay", kvs[1].name);
	ELA_ASSERT_STR_EQ("3", kvs[1].value);
	ela_uboot_env_free_kvs(kvs, count);
}

static void test_parse_existing_env_data_with_offset(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;
	/* First 4 bytes are "header", data starts at offset 4 */
	static const uint8_t buf[] = "\xAB\xCD\xEF\x01" "x=1\0\0";

	ELA_ASSERT_INT_EQ(0, ela_uboot_parse_existing_env_data(buf, sizeof(buf) - 1, 4, &kvs, &count));
	ELA_ASSERT_INT_EQ(1, count);
	ELA_ASSERT_STR_EQ("x", kvs[0].name);
	ela_uboot_env_free_kvs(kvs, count);
}

/* =========================================================================
 * ela_uboot_build_env_region
 * ====================================================================== */

static void test_build_env_region_null_out(void)
{
	uint8_t buf[32];
	struct env_kv kv = { "k", "v" };

	ELA_ASSERT_INT_EQ(-1, ela_uboot_build_env_region(&kv, 1, NULL, 32));
	ELA_ASSERT_INT_EQ(-1, ela_uboot_build_env_region(&kv, 1, buf, 0));
	ELA_ASSERT_INT_EQ(-1, ela_uboot_build_env_region(&kv, 1, buf, 1));
}

static void test_build_env_region_empty_kvs(void)
{
	uint8_t buf[8] = { 0xFF };

	ELA_ASSERT_INT_EQ(0, ela_uboot_build_env_region(NULL, 0, buf, sizeof(buf)));
	/* Double NUL terminator */
	ELA_ASSERT_INT_EQ(0, buf[0]);
	ELA_ASSERT_INT_EQ(0, buf[1]);
}

static void test_build_env_region_roundtrip(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;
	uint8_t region[64];
	struct env_kv *back = NULL;
	size_t back_count = 0;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "bootdelay", "5"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "stdin", "serial"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_build_env_region(kvs, count, region, sizeof(region)));
	ELA_ASSERT_TRUE(memmem(region, sizeof(region), "bootdelay=5", 11) != NULL);
	ELA_ASSERT_TRUE(memmem(region, sizeof(region), "stdin=serial", 12) != NULL);
	ELA_ASSERT_INT_EQ(0, ela_uboot_parse_existing_env_data(region, sizeof(region), 0, &back, &back_count));
	ELA_ASSERT_INT_EQ(2, back_count);
	ela_uboot_env_free_kvs(kvs, count);
	ela_uboot_env_free_kvs(back, back_count);
}

static void test_build_env_region_too_small(void)
{
	uint8_t buf[4];
	struct env_kv kv = { "longname", "longvalue" };

	ELA_ASSERT_INT_EQ(-1, ela_uboot_build_env_region(&kv, 1, buf, sizeof(buf)));
}

/* =========================================================================
 * ela_uboot_env_crc_matches
 * ====================================================================== */

static void test_env_crc_matches_null_inputs(void)
{
	uint32_t table[256];
	uint8_t buf[16] = {0};
	bool is_le = false;

	ela_crc32_init(table);
	ELA_ASSERT_FALSE(ela_uboot_env_crc_matches(NULL, buf, sizeof(buf), 4, &is_le));
	ELA_ASSERT_FALSE(ela_uboot_env_crc_matches(table, NULL, sizeof(buf), 4, &is_le));
	ELA_ASSERT_FALSE(ela_uboot_env_crc_matches(table, buf, sizeof(buf), 4, NULL));
}

static void test_env_crc_matches_data_off_ge_env_size(void)
{
	uint32_t table[256];
	uint8_t buf[16] = {0};
	bool is_le = false;

	ela_crc32_init(table);
	ELA_ASSERT_FALSE(ela_uboot_env_crc_matches(table, buf, 4, 4, &is_le));
	ELA_ASSERT_FALSE(ela_uboot_env_crc_matches(table, buf, 3, 4, &is_le));
}

static void test_env_crc_matches_mismatch(void)
{
	uint32_t table[256];
	uint8_t buf[16] = {0};
	bool is_le = false;

	ela_crc32_init(table);
	/* All-zero CRC bytes won't match computed CRC */
	ELA_ASSERT_FALSE(ela_uboot_env_crc_matches(table, buf, sizeof(buf), 4, &is_le));
}

static void test_env_crc_matches_le(void)
{
	uint32_t table[256];
	uint8_t buf[16] = {0};
	uint32_t crc;
	bool is_le = false;

	ela_crc32_init(table);
	memcpy(buf + 4, "a=b\0\0", 5);
	crc = ela_crc32_calc(table, buf + 4, sizeof(buf) - 4);
	buf[0] = (uint8_t)crc;
	buf[1] = (uint8_t)(crc >> 8);
	buf[2] = (uint8_t)(crc >> 16);
	buf[3] = (uint8_t)(crc >> 24);
	ELA_ASSERT_TRUE(ela_uboot_env_crc_matches(table, buf, sizeof(buf), 4, &is_le));
	ELA_ASSERT_TRUE(is_le);
}

static void test_env_crc_matches_be(void)
{
	uint32_t table[256];
	uint8_t buf[16] = {0};
	uint32_t crc;
	bool is_le = true;

	ela_crc32_init(table);
	memcpy(buf + 4, "a=b\0\0", 5);
	crc = ela_crc32_calc(table, buf + 4, sizeof(buf) - 4);
	/* Store as big-endian */
	buf[0] = (uint8_t)(crc >> 24);
	buf[1] = (uint8_t)(crc >> 16);
	buf[2] = (uint8_t)(crc >> 8);
	buf[3] = (uint8_t)crc;
	ELA_ASSERT_TRUE(ela_uboot_env_crc_matches(table, buf, sizeof(buf), 4, &is_le));
	ELA_ASSERT_FALSE(is_le);
}

static void test_env_crc_matches_redundant_offset(void)
{
	uint32_t table[256];
	uint8_t buf[16] = {0};
	uint32_t crc;
	bool is_le = false;

	ela_crc32_init(table);
	/* Redundant env layout: data starts at offset 5 */
	memcpy(buf + 5, "x=1\0", 4);
	crc = ela_crc32_calc(table, buf + 5, sizeof(buf) - 5);
	buf[0] = (uint8_t)crc;
	buf[1] = (uint8_t)(crc >> 8);
	buf[2] = (uint8_t)(crc >> 16);
	buf[3] = (uint8_t)(crc >> 24);
	ELA_ASSERT_TRUE(ela_uboot_env_crc_matches(table, buf, sizeof(buf), 5, &is_le));
}

/* =========================================================================
 * Combined flow: set/build/parse roundtrip via CRC
 * ====================================================================== */

static void test_set_unset_and_build_region(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;
	uint8_t region[64];

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "bootcmd", "run boot"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "bootdelay", "3"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "bootdelay", "5"));
	ELA_ASSERT_INT_EQ(2, count);
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_unset_kv(kvs, &count, "bootcmd"));
	ELA_ASSERT_INT_EQ(1, count);
	ELA_ASSERT_INT_EQ(0, ela_uboot_build_env_region(kvs, count, region, sizeof(region)));
	ELA_ASSERT_TRUE(memmem(region, sizeof(region), "bootdelay=5", 11) != NULL);
	ela_uboot_env_free_kvs(kvs, count);
}

static void test_parse_fw_config_line_and_existing_env_data(void)
{
	struct uboot_cfg_entry cfg;
	static const uint8_t envbuf[] = "bootcmd=run boot\0bootdelay=3\0\0";
	struct env_kv *kvs = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(1, ela_uboot_parse_fw_config_line("/dev/mtd0 0x0 0x2000 0x2000 1", &cfg));
	ELA_ASSERT_STR_EQ("/dev/mtd0", cfg.dev);
	ELA_ASSERT_INT_EQ(0x2000, cfg.env_size);
	ELA_ASSERT_INT_EQ(0, ela_uboot_parse_existing_env_data(envbuf, sizeof(envbuf) - 1, 0, &kvs, &count));
	ELA_ASSERT_INT_EQ(2, count);
	ELA_ASSERT_STR_EQ("bootcmd", kvs[0].name);
	ELA_ASSERT_STR_EQ("3", kvs[1].value);
	ela_uboot_env_free_kvs(kvs, count);
}

static void test_uboot_env_crc_matches_detects_endianness(void)
{
	uint32_t table[256];
	uint8_t buf[16] = {0};
	uint32_t crc;
	bool is_le = false;

	ela_crc32_init(table);
	memcpy(buf + 4, "a=b\0\0", 5);
	crc = ela_crc32_calc(table, buf + 4, sizeof(buf) - 4);
	buf[0] = (uint8_t)crc;
	buf[1] = (uint8_t)(crc >> 8);
	buf[2] = (uint8_t)(crc >> 16);
	buf[3] = (uint8_t)(crc >> 24);
	ELA_ASSERT_TRUE(ela_uboot_env_crc_matches(table, buf, sizeof(buf), 4, &is_le));
	ELA_ASSERT_TRUE(is_le);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_env_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* set_kv */
		{ "set_kv_null_inputs",             test_set_kv_null_inputs },
		{ "set_kv_adds_new_entry",          test_set_kv_adds_new_entry },
		{ "set_kv_update_existing",         test_set_kv_update_existing },
		{ "set_kv_multiple_keys",           test_set_kv_multiple_distinct_keys },
		/* unset_kv */
		{ "unset_kv_null_inputs",           test_unset_kv_null_inputs },
		{ "unset_kv_nonexistent_ok",        test_unset_kv_nonexistent_is_ok },
		{ "unset_kv_removes_only",          test_unset_kv_removes_only_element },
		{ "unset_kv_middle_shifts",         test_unset_kv_middle_element_shifts },
		/* parse_fw_config_line */
		{ "parse_fw_null",                  test_parse_fw_config_line_null },
		{ "parse_fw_null_out",              test_parse_fw_config_line_null_out },
		{ "parse_fw_blank",                 test_parse_fw_config_line_blank },
		{ "parse_fw_comment",               test_parse_fw_config_line_comment },
		{ "parse_fw_too_few_fields",        test_parse_fw_config_line_too_few_fields },
		{ "parse_fw_invalid_offset",        test_parse_fw_config_line_invalid_offset },
		{ "parse_fw_zero_env_size",         test_parse_fw_config_line_zero_env_size },
		{ "parse_fw_too_small_env_size",    test_parse_fw_config_line_too_small_env_size },
		{ "parse_fw_valid_fields",          test_parse_fw_config_line_valid_parses_fields },
		{ "parse_fw_nonzero_offset",        test_parse_fw_config_line_nonzero_offset },
		{ "parse_fw_leading_whitespace",    test_parse_fw_config_line_leading_whitespace },
		/* parse_existing_env_data */
		{ "parse_env_null",                 test_parse_existing_env_data_null },
		{ "parse_env_offset_past_end",      test_parse_existing_env_data_offset_past_end },
		{ "parse_env_empty",                test_parse_existing_env_data_empty },
		{ "parse_env_no_eq_skipped",        test_parse_existing_env_data_no_eq_skipped },
		{ "parse_env_two_pairs",            test_parse_existing_env_data_two_pairs },
		{ "parse_env_with_offset",          test_parse_existing_env_data_with_offset },
		/* build_env_region */
		{ "build_null_out",                 test_build_env_region_null_out },
		{ "build_empty_kvs",                test_build_env_region_empty_kvs },
		{ "build_roundtrip",                test_build_env_region_roundtrip },
		{ "build_too_small",                test_build_env_region_too_small },
		/* env_crc_matches */
		{ "crc_null_inputs",                test_env_crc_matches_null_inputs },
		{ "crc_data_off_ge_env_size",       test_env_crc_matches_data_off_ge_env_size },
		{ "crc_mismatch",                   test_env_crc_matches_mismatch },
		{ "crc_le_match",                   test_env_crc_matches_le },
		{ "crc_be_match",                   test_env_crc_matches_be },
		{ "crc_redundant_offset",           test_env_crc_matches_redundant_offset },
		/* legacy combined tests */
		{ "uboot_env_set_unset_and_build_region",              test_set_unset_and_build_region },
		{ "uboot_parse_fw_config_line_and_existing_env_data",  test_parse_fw_config_line_and_existing_env_data },
		{ "uboot_env_crc_matches_detects_endianness",          test_uboot_env_crc_matches_detects_endianness },
	};

	return ela_run_test_suite("uboot_env_util", cases, sizeof(cases) / sizeof(cases[0]));
}
