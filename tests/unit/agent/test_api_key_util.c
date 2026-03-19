// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/api_key_util.h"

#include <string.h>

static void test_api_key_line_normalize_trims_newlines(void)
{
	char line[] = "token123\r\n";

	ELA_ASSERT_INT_EQ(0, ela_api_key_line_normalize(line));
	ELA_ASSERT_STR_EQ("token123", line);
}

static void test_api_key_add_unique_deduplicates_and_limits(void)
{
	char keys[2][ELA_API_KEY_MAX_LEN + 1] = {{0}};
	int count = 0;

	ELA_ASSERT_INT_EQ(0, ela_api_key_add_unique(keys, &count, 2, "alpha"));
	ELA_ASSERT_INT_EQ(1, ela_api_key_add_unique(keys, &count, 2, "alpha"));
	ELA_ASSERT_INT_EQ(0, ela_api_key_add_unique(keys, &count, 2, "beta"));
	ELA_ASSERT_INT_EQ(-1, ela_api_key_add_unique(keys, &count, 2, "gamma"));
	ELA_ASSERT_INT_EQ(2, count);
}

int run_api_key_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "api_key_line_normalize_trims_newlines", test_api_key_line_normalize_trims_newlines },
		{ "api_key_add_unique_deduplicates_and_limits", test_api_key_add_unique_deduplicates_and_limits },
	};

	return ela_run_test_suite("api_key_util", cases, sizeof(cases) / sizeof(cases[0]));
}
