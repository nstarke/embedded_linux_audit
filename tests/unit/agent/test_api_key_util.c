// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/api_key_util.h"

#include <string.h>

/* =========================================================================
 * ela_api_key_line_normalize
 * ====================================================================== */

static void test_normalize_null_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_api_key_line_normalize(NULL));
}

static void test_normalize_empty_returns_minus1(void)
{
	char line[] = "";

	ELA_ASSERT_INT_EQ(-1, ela_api_key_line_normalize(line));
}

static void test_normalize_only_newlines_returns_minus1(void)
{
	char line[] = "\r\n";

	ELA_ASSERT_INT_EQ(-1, ela_api_key_line_normalize(line));
}

static void test_normalize_trims_crlf(void)
{
	char line[] = "token123\r\n";

	ELA_ASSERT_INT_EQ(0, ela_api_key_line_normalize(line));
	ELA_ASSERT_STR_EQ("token123", line);
}

static void test_normalize_trims_lf_only(void)
{
	char line[] = "mykey\n";

	ELA_ASSERT_INT_EQ(0, ela_api_key_line_normalize(line));
	ELA_ASSERT_STR_EQ("mykey", line);
}

static void test_normalize_no_newline_ok(void)
{
	char line[] = "plaintoken";

	ELA_ASSERT_INT_EQ(0, ela_api_key_line_normalize(line));
	ELA_ASSERT_STR_EQ("plaintoken", line);
}

/* =========================================================================
 * ela_api_key_add_unique
 * ====================================================================== */

static void test_add_null_keys_returns_minus1(void)
{
	int count = 0;

	ELA_ASSERT_INT_EQ(-1, ela_api_key_add_unique(NULL, &count, 2, "alpha"));
}

static void test_add_null_count_returns_minus1(void)
{
	char keys[2][ELA_API_KEY_MAX_LEN + 1] = {{0}};

	ELA_ASSERT_INT_EQ(-1, ela_api_key_add_unique(keys, NULL, 2, "alpha"));
}

static void test_add_null_key_returns_minus1(void)
{
	char keys[2][ELA_API_KEY_MAX_LEN + 1] = {{0}};
	int count = 0;

	ELA_ASSERT_INT_EQ(-1, ela_api_key_add_unique(keys, &count, 2, NULL));
}

static void test_add_empty_key_returns_minus1(void)
{
	char keys[2][ELA_API_KEY_MAX_LEN + 1] = {{0}};
	int count = 0;

	ELA_ASSERT_INT_EQ(-1, ela_api_key_add_unique(keys, &count, 2, ""));
}

static void test_add_too_long_key_returns_minus1(void)
{
	char keys[2][ELA_API_KEY_MAX_LEN + 1] = {{0}};
	int count = 0;
	/* build a string that is one byte longer than the max */
	char long_key[ELA_API_KEY_MAX_LEN + 2];

	memset(long_key, 'x', ELA_API_KEY_MAX_LEN + 1);
	long_key[ELA_API_KEY_MAX_LEN + 1] = '\0';

	ELA_ASSERT_INT_EQ(-1, ela_api_key_add_unique(keys, &count, 2, long_key));
}

static void test_add_simple_adds_and_increments_count(void)
{
	char keys[2][ELA_API_KEY_MAX_LEN + 1] = {{0}};
	int count = 0;

	ELA_ASSERT_INT_EQ(0, ela_api_key_add_unique(keys, &count, 2, "alpha"));
	ELA_ASSERT_INT_EQ(1, count);
	ELA_ASSERT_STR_EQ("alpha", keys[0]);
}

static void test_add_duplicate_returns_one(void)
{
	char keys[2][ELA_API_KEY_MAX_LEN + 1] = {{0}};
	int count = 0;

	ELA_ASSERT_INT_EQ(0, ela_api_key_add_unique(keys, &count, 2, "alpha"));
	ELA_ASSERT_INT_EQ(1, ela_api_key_add_unique(keys, &count, 2, "alpha"));
	ELA_ASSERT_INT_EQ(1, count); /* count must not grow */
}

static void test_add_fills_to_max_then_returns_minus1(void)
{
	char keys[2][ELA_API_KEY_MAX_LEN + 1] = {{0}};
	int count = 0;

	ELA_ASSERT_INT_EQ(0,  ela_api_key_add_unique(keys, &count, 2, "alpha"));
	ELA_ASSERT_INT_EQ(0,  ela_api_key_add_unique(keys, &count, 2, "beta"));
	ELA_ASSERT_INT_EQ(-1, ela_api_key_add_unique(keys, &count, 2, "gamma"));
	ELA_ASSERT_INT_EQ(2, count);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_api_key_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* ela_api_key_line_normalize */
		{ "normalize/null",               test_normalize_null_returns_minus1 },
		{ "normalize/empty",              test_normalize_empty_returns_minus1 },
		{ "normalize/only_newlines",      test_normalize_only_newlines_returns_minus1 },
		{ "normalize/trims_crlf",         test_normalize_trims_crlf },
		{ "normalize/trims_lf",           test_normalize_trims_lf_only },
		{ "normalize/no_newline_ok",      test_normalize_no_newline_ok },
		/* ela_api_key_add_unique */
		{ "add/null_keys",                test_add_null_keys_returns_minus1 },
		{ "add/null_count",               test_add_null_count_returns_minus1 },
		{ "add/null_key",                 test_add_null_key_returns_minus1 },
		{ "add/empty_key",                test_add_empty_key_returns_minus1 },
		{ "add/too_long_key",             test_add_too_long_key_returns_minus1 },
		{ "add/simple",                   test_add_simple_adds_and_increments_count },
		{ "add/duplicate",                test_add_duplicate_returns_one },
		{ "add/limit",                    test_add_fills_to_max_then_returns_minus1 },
	};

	return ela_run_test_suite("api_key_util", cases, sizeof(cases) / sizeof(cases[0]));
}
