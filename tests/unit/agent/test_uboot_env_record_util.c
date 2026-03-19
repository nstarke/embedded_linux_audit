// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/env/uboot_env_record_util.h"

#include <stdlib.h>
#include <string.h>

static void test_uboot_env_record_mode_helper(void)
{
	ELA_ASSERT_STR_EQ("hint-only", ela_uboot_env_candidate_mode(true, false, false));
	ELA_ASSERT_STR_EQ("redundant", ela_uboot_env_candidate_mode(false, false, true));
	ELA_ASSERT_STR_EQ("standard", ela_uboot_env_candidate_mode(false, true, false));
}

static void test_uboot_env_record_data_offset_helper(void)
{
	ELA_ASSERT_INT_EQ(4, (int)ela_uboot_env_data_offset(true, false));
	ELA_ASSERT_INT_EQ(5, (int)ela_uboot_env_data_offset(false, true));
}

static void test_uboot_env_record_formatter_helpers(void)
{
	char *out = NULL;
	bool csv_header_emitted = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_candidate_record(0,
								   &csv_header_emitted,
								   "/dev/mtd0",
								   0x1000,
								   "LE",
								   "standard",
								   true,
								   0x1000,
								   0x2000,
								   0x1000,
								   0x2,
								   &out));
	ELA_ASSERT_TRUE(strstr(out, "candidate offset=0x1000") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "uboot_env.config line: /dev/mtd0 0x1000 0x2000 0x1000 0x2") != NULL);
	free(out);
	out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_candidate_record(1,
								   &csv_header_emitted,
								   "/dev/mtd0",
								   0x1000,
								   "LE",
								   "standard",
								   true,
								   0x1000,
								   0x2000,
								   0x1000,
								   0x2,
								   &out));
	ELA_ASSERT_TRUE(strstr(out, "record,device,offset,crc_endian,mode,has_known_vars,cfg_offset,env_size,erase_size,sector_count\n") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "env_candidate") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "/dev/mtd0") != NULL);
	free(out);
	out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_redundant_pair_record(2,
									&csv_header_emitted,
									"/dev/mtd0",
									0x1000,
									0x2000,
									&out));
	ELA_ASSERT_TRUE(strstr(out, "\"record\":\"redundant_pair\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"offset_a\":4096") != NULL);
	free(out);
}

static void test_uboot_env_verbose_and_vars_dump_helpers(void)
{
	char *out = NULL;
	bool csv_header_emitted = false;
	static const uint8_t vars_blob[] = "bootcmd=run boot\0baudrate=115200\0\0";

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_scan_start_record(2,
								    true,
								    &csv_header_emitted,
								    "/dev/mtd1",
								    0x1000,
								    0x2000,
								    0x3000,
								    &out));
	ELA_ASSERT_TRUE(strstr(out, "\"message\":\"Scanning /dev/mtd1") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"step\":4096") != NULL);
	free(out);
	out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_vars_dump(0,
							    "/dev/mtd1",
							    0x4000,
							    vars_blob,
							    sizeof(vars_blob) - 1,
							    &out));
	ELA_ASSERT_TRUE(strstr(out, "parsed env vars:") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "bootcmd=run boot") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "baudrate=115200") != NULL);
	free(out);
	out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_format_vars_dump(2,
							    "/dev/mtd1",
							    0x4000,
							    vars_blob,
							    sizeof(vars_blob) - 1,
							    &out));
	ELA_ASSERT_TRUE(strstr(out, "\"record\":\"env_vars\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"key\":\"bootcmd\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"value\":\"run boot\"") != NULL);
	free(out);
}

int run_uboot_env_record_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "uboot_env_record_mode_helper", test_uboot_env_record_mode_helper },
		{ "uboot_env_record_data_offset_helper", test_uboot_env_record_data_offset_helper },
		{ "uboot_env_record_formatter_helpers", test_uboot_env_record_formatter_helpers },
		{ "uboot_env_verbose_and_vars_dump_helpers", test_uboot_env_verbose_and_vars_dump_helpers },
	};

	return ela_run_test_suite("uboot_env_record_util", cases, sizeof(cases) / sizeof(cases[0]));
}
