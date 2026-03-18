// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/env/uboot_env_record_util.h"

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

int run_uboot_env_record_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "uboot_env_record_mode_helper", test_uboot_env_record_mode_helper },
		{ "uboot_env_record_data_offset_helper", test_uboot_env_record_data_offset_helper },
	};

	return ela_run_test_suite("uboot_env_record_util", cases, sizeof(cases) / sizeof(cases[0]));
}
