// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/env/uboot_env_record_util.h"
#include "../../../agent/uboot/env/uboot_env_format_util.h"

#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * ela_uboot_env_candidate_mode
 * ====================================================================== */

static void test_mode_bruteforce_hint_only(void)
{
	ELA_ASSERT_STR_EQ("hint-only", ela_uboot_env_candidate_mode(true, false, false));
}

static void test_mode_bruteforce_overrides_crc_flags(void)
{
	ELA_ASSERT_STR_EQ("hint-only", ela_uboot_env_candidate_mode(true, true, true));
}

static void test_mode_std_only(void)
{
	ELA_ASSERT_STR_EQ("standard", ela_uboot_env_candidate_mode(false, true, false));
}

static void test_mode_redund_only(void)
{
	ELA_ASSERT_STR_EQ("redundant", ela_uboot_env_candidate_mode(false, false, true));
}

static void test_mode_both_crc_ok(void)
{
	/* redundant requires crc_ok_redund && !crc_ok_std; both → "standard" */
	ELA_ASSERT_STR_EQ("standard", ela_uboot_env_candidate_mode(false, true, true));
}

static void test_mode_neither_crc_ok(void)
{
	ELA_ASSERT_STR_EQ("standard", ela_uboot_env_candidate_mode(false, false, false));
}

/* =========================================================================
 * ela_uboot_env_data_offset
 * ====================================================================== */

static void test_data_offset_std_only(void)
{
	ELA_ASSERT_INT_EQ(4, (int)ela_uboot_env_data_offset(true, false));
}

static void test_data_offset_redund(void)
{
	ELA_ASSERT_INT_EQ(5, (int)ela_uboot_env_data_offset(false, true));
}

static void test_data_offset_both(void)
{
	ELA_ASSERT_INT_EQ(5, (int)ela_uboot_env_data_offset(true, true));
}

static void test_data_offset_neither(void)
{
	ELA_ASSERT_INT_EQ(4, (int)ela_uboot_env_data_offset(false, false));
}

/* =========================================================================
 * ela_uboot_env_format_candidate_record
 * ====================================================================== */

static void test_candidate_record_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_format_candidate_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, NULL, "/dev/mtd0", 0x1000,
		"LE", "standard", true, 0x1000, 0x2000, 0x1000, 2, NULL));
}

static void test_candidate_record_txt_standard(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_candidate_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, &hdr, "/dev/mtd0", 0x1000,
		"LE", "standard", true, 0x1000, 0x2000, 0x1000, 2, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "candidate offset=0x1000") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "crc=LE-endian") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "has known vars") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "uboot_env.config line: /dev/mtd0 0x1000 0x2000 0x1000 0x2") != NULL);
	free(out);
}

static void test_candidate_record_txt_redundant(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_candidate_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, &hdr, "/dev/mtd0", 0x1000,
		"BE", "redundant", false, 0x1000, 0x2000, 0x1000, 1, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "redundant-env layout") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "crc ok") != NULL);
	free(out);
}

static void test_candidate_record_txt_hint_only(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_candidate_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, &hdr, "/dev/mtd0", 0x1000,
		NULL, "hint-only", true, 0x1000, 0x2000, 0x1000, 1, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "mode=hint-only") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "has known vars") != NULL);
	free(out);
}

static void test_candidate_record_csv(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_candidate_record(
		ELA_UBOOT_ENV_OUTPUT_CSV, &hdr, "/dev/mtd0", 0x1000,
		"LE", "standard", true, 0x1000, 0x2000, 0x1000, 2, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "record,device,offset") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "env_candidate") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "/dev/mtd0") != NULL);
	ELA_ASSERT_TRUE(hdr);
	free(out);
}

static void test_candidate_record_csv_header_once(void)
{
	char *out1 = NULL, *out2 = NULL;
	bool hdr = false;

	ela_uboot_env_format_candidate_record(
		ELA_UBOOT_ENV_OUTPUT_CSV, &hdr, "/dev/mtd0", 0x1000,
		"LE", "standard", true, 0x1000, 0x2000, 0x1000, 1, &out1);
	ela_uboot_env_format_candidate_record(
		ELA_UBOOT_ENV_OUTPUT_CSV, &hdr, "/dev/mtd1", 0x2000,
		"LE", "standard", true, 0x2000, 0x2000, 0x1000, 1, &out2);
	/* Second record should not contain the header */
	ELA_ASSERT_TRUE(strstr(out2, "record,device,offset") == NULL);
	free(out1);
	free(out2);
}

static void test_candidate_record_json(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_candidate_record(
		ELA_UBOOT_ENV_OUTPUT_JSON, &hdr, "/dev/mtd0", 0x1000,
		"LE", "standard", true, 0x1000, 0x2000, 0x1000, 2, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"record\":\"env_candidate\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"device\":\"/dev/mtd0\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"offset\":4096") != NULL);
	free(out);
}

/* =========================================================================
 * ela_uboot_env_format_redundant_pair_record
 * ====================================================================== */

static void test_redundant_pair_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_format_redundant_pair_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, NULL, "/dev/mtd0", 0x1000, 0x2000, NULL));
}

static void test_redundant_pair_txt(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_redundant_pair_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, &hdr, "/dev/mtd0", 0x1000, 0x2000, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "redundant env candidate pair") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "/dev/mtd0") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "0x1000") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "0x2000") != NULL);
	free(out);
}

static void test_redundant_pair_csv(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_redundant_pair_record(
		ELA_UBOOT_ENV_OUTPUT_CSV, &hdr, "/dev/mtd0", 0x1000, 0x2000, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "redundant_pair") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "/dev/mtd0") != NULL);
	free(out);
}

static void test_redundant_pair_json(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_redundant_pair_record(
		ELA_UBOOT_ENV_OUTPUT_JSON, &hdr, "/dev/mtd0", 0x1000, 0x2000, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"record\":\"redundant_pair\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"offset_a\":4096") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"offset_b\":8192") != NULL);
	free(out);
}

/* =========================================================================
 * ela_uboot_env_format_verbose_record
 * ====================================================================== */

static void test_verbose_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_format_verbose_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, true, NULL, "/dev/mtd0", 0, "msg", NULL));
}

static void test_verbose_not_verbose(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_verbose_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, false, &hdr, "/dev/mtd0", 0, "msg", &out));
	ELA_ASSERT_TRUE(out == NULL);
}

static void test_verbose_null_msg(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_verbose_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, true, &hdr, "/dev/mtd0", 0, NULL, &out));
	ELA_ASSERT_TRUE(out == NULL);
}

static void test_verbose_txt(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_verbose_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, true, &hdr, "/dev/mtd0", 0x1000,
		"test message", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "test message") != NULL);
	free(out);
}

static void test_verbose_csv(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_verbose_record(
		ELA_UBOOT_ENV_OUTPUT_CSV, true, &hdr, "/dev/mtd0", 0x1000,
		"test message", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "verbose") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "test message") != NULL);
	free(out);
}

static void test_verbose_json(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_verbose_record(
		ELA_UBOOT_ENV_OUTPUT_JSON, true, &hdr, "/dev/mtd0", 0x1000,
		"test message", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"record\":\"verbose\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"message\":\"test message\"") != NULL);
	free(out);
}

/* =========================================================================
 * ela_uboot_env_format_scan_start_record
 * ====================================================================== */

static void test_scan_start_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_format_scan_start_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, true, NULL, "/dev/mtd0",
		0x1000, 0x2000, 0x100000, NULL));
}

static void test_scan_start_not_verbose(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_scan_start_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, false, &hdr, "/dev/mtd0",
		0x1000, 0x2000, 0x100000, &out));
	ELA_ASSERT_TRUE(out == NULL);
}

static void test_scan_start_txt(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_scan_start_record(
		ELA_UBOOT_ENV_OUTPUT_TXT, true, &hdr, "/dev/mtd0",
		0x1000, 0x2000, 0x100000, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "Scanning /dev/mtd0") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "step=0x1000") != NULL);
	free(out);
}

static void test_scan_start_json(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_scan_start_record(
		ELA_UBOOT_ENV_OUTPUT_JSON, true, &hdr, "/dev/mtd1",
		0x1000, 0x2000, 0x3000, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"message\":\"Scanning /dev/mtd1") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"step\":4096") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"env_size\":8192") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"device_size\":12288") != NULL);
	free(out);
}

/* =========================================================================
 * ela_uboot_env_format_vars_dump
 * ====================================================================== */

static void test_vars_dump_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_format_vars_dump(
		ELA_UBOOT_ENV_OUTPUT_TXT, "/dev/mtd0", 0, NULL, 0, NULL));
}

static void test_vars_dump_null_data_txt(void)
{
	char *out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_vars_dump(
		ELA_UBOOT_ENV_OUTPUT_TXT, "/dev/mtd0", 0, NULL, 0, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "parsed env vars:") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "no parseable variables found") != NULL);
	free(out);
}

static void test_vars_dump_txt_two_vars(void)
{
	static const uint8_t d[] = "bootcmd=run boot\0baudrate=115200\0\0";
	char *out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_vars_dump(
		ELA_UBOOT_ENV_OUTPUT_TXT, "/dev/mtd0", 0x4000,
		d, sizeof(d) - 1, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "bootcmd=run boot") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "baudrate=115200") != NULL);
	free(out);
}

static void test_vars_dump_txt_no_vars(void)
{
	static const uint8_t d[] = "\0\0";
	char *out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_vars_dump(
		ELA_UBOOT_ENV_OUTPUT_TXT, "/dev/mtd0", 0,
		d, sizeof(d) - 1, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "no parseable variables found") != NULL);
	free(out);
}

static void test_vars_dump_json(void)
{
	static const uint8_t d[] = "bootcmd=run boot\0baudrate=115200\0\0";
	char *out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_vars_dump(
		ELA_UBOOT_ENV_OUTPUT_JSON, "/dev/mtd1", 0x4000,
		d, sizeof(d) - 1, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"record\":\"env_vars\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"key\":\"bootcmd\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"value\":\"run boot\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"key\":\"baudrate\"") != NULL);
	free(out);
}

static void test_vars_dump_json_null_data(void)
{
	char *out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_vars_dump(
		ELA_UBOOT_ENV_OUTPUT_JSON, "/dev/mtd0", 0, NULL, 0, &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"record\":\"env_vars\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"vars\":[]") != NULL);
	free(out);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_env_record_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "mode_bruteforce_hint_only",          test_mode_bruteforce_hint_only },
		{ "mode_bruteforce_overrides_crc",      test_mode_bruteforce_overrides_crc_flags },
		{ "mode_std_only",                      test_mode_std_only },
		{ "mode_redund_only",                   test_mode_redund_only },
		{ "mode_both_crc_ok",                   test_mode_both_crc_ok },
		{ "mode_neither_crc_ok",                test_mode_neither_crc_ok },
		{ "data_offset_std_only",               test_data_offset_std_only },
		{ "data_offset_redund",                 test_data_offset_redund },
		{ "data_offset_both",                   test_data_offset_both },
		{ "data_offset_neither",                test_data_offset_neither },
		{ "candidate_null_out",                 test_candidate_record_null_out },
		{ "candidate_txt_standard",             test_candidate_record_txt_standard },
		{ "candidate_txt_redundant",            test_candidate_record_txt_redundant },
		{ "candidate_txt_hint_only",            test_candidate_record_txt_hint_only },
		{ "candidate_csv",                      test_candidate_record_csv },
		{ "candidate_csv_header_once",          test_candidate_record_csv_header_once },
		{ "candidate_json",                     test_candidate_record_json },
		{ "redundant_pair_null_out",            test_redundant_pair_null_out },
		{ "redundant_pair_txt",                 test_redundant_pair_txt },
		{ "redundant_pair_csv",                 test_redundant_pair_csv },
		{ "redundant_pair_json",                test_redundant_pair_json },
		{ "verbose_null_out",                   test_verbose_null_out },
		{ "verbose_not_verbose",                test_verbose_not_verbose },
		{ "verbose_null_msg",                   test_verbose_null_msg },
		{ "verbose_txt",                        test_verbose_txt },
		{ "verbose_csv",                        test_verbose_csv },
		{ "verbose_json",                       test_verbose_json },
		{ "scan_start_null_out",                test_scan_start_null_out },
		{ "scan_start_not_verbose",             test_scan_start_not_verbose },
		{ "scan_start_txt",                     test_scan_start_txt },
		{ "scan_start_json",                    test_scan_start_json },
		{ "vars_dump_null_out",                 test_vars_dump_null_out },
		{ "vars_dump_null_data_txt",            test_vars_dump_null_data_txt },
		{ "vars_dump_txt_two_vars",             test_vars_dump_txt_two_vars },
		{ "vars_dump_txt_no_vars",              test_vars_dump_txt_no_vars },
		{ "vars_dump_json",                     test_vars_dump_json },
		{ "vars_dump_json_null_data",           test_vars_dump_json_null_data },
	};
	return ela_run_test_suite("uboot_env_record_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
