// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/env/uboot_env_scan_util.h"

#include <stdlib.h>

static void test_uboot_env_candidate_merge_and_http_source_helper(void)
{
	struct ela_uboot_env_candidate *cands = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_add_or_merge_candidate(&cands, &count, 0x1000, true, false));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_add_or_merge_candidate(&cands, &count, 0x1000, false, true));
	ELA_ASSERT_INT_EQ(1, count);
	ELA_ASSERT_TRUE(cands[0].crc_standard);
	ELA_ASSERT_TRUE(cands[0].crc_redundant);
	ELA_ASSERT_TRUE(ela_uboot_env_is_http_write_source("https://ela.example/script"));
	ELA_ASSERT_FALSE(ela_uboot_env_is_http_write_source("/tmp/write.env"));
	ELA_ASSERT_TRUE(ela_uboot_env_should_report_redundant_pair(0x1000, 0x2000, 0x1000, 2));
	ELA_ASSERT_TRUE(ela_uboot_env_should_report_redundant_pair(0x1000, 0x3000, 0x1000, 2));
	ELA_ASSERT_FALSE(ela_uboot_env_should_report_redundant_pair(0x1000, 0x2800, 0x1000, 2));
	free(cands);
}

int run_uboot_env_scan_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "uboot_env_candidate_merge_and_http_source_helper", test_uboot_env_candidate_merge_and_http_source_helper },
	};

	return ela_run_test_suite("uboot_env_scan_util", cases, sizeof(cases) / sizeof(cases[0]));
}
