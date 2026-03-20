// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/command_parse_util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * ela_parse_positive_size_arg
 * ====================================================================== */

static void test_size_null_spec_returns_minus1(void)
{
	size_t value = 0;

	ELA_ASSERT_INT_EQ(-1, ela_parse_positive_size_arg(NULL, &value));
}

static void test_size_null_out_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_parse_positive_size_arg("42", NULL));
}

static void test_size_empty_string_returns_minus1(void)
{
	size_t value = 0;

	ELA_ASSERT_INT_EQ(-1, ela_parse_positive_size_arg("", &value));
}

static void test_size_zero_returns_minus1(void)
{
	size_t value = 0;

	ELA_ASSERT_INT_EQ(-1, ela_parse_positive_size_arg("0", &value));
}

static void test_size_negative_returns_minus1(void)
{
	size_t value = 0;

	ELA_ASSERT_INT_EQ(-1, ela_parse_positive_size_arg("-1", &value));
}

static void test_size_non_numeric_returns_minus1(void)
{
	size_t value = 0;

	ELA_ASSERT_INT_EQ(-1, ela_parse_positive_size_arg("abc", &value));
}

static void test_size_trailing_chars_returns_minus1(void)
{
	size_t value = 0;

	/* base-10 only; trailing 'k' is not accepted */
	ELA_ASSERT_INT_EQ(-1, ela_parse_positive_size_arg("42k", &value));
}

static void test_size_valid_decimal(void)
{
	size_t value = 0;

	ELA_ASSERT_INT_EQ(0, ela_parse_positive_size_arg("42", &value));
	ELA_ASSERT_INT_EQ(42, (int)value);
}

static void test_size_one_is_valid(void)
{
	size_t value = 0;

	ELA_ASSERT_INT_EQ(0, ela_parse_positive_size_arg("1", &value));
	ELA_ASSERT_INT_EQ(1, (int)value);
}

/* =========================================================================
 * ela_parse_u32
 * ====================================================================== */

static void test_u32_null_text_returns_minus1(void)
{
	uint32_t v = 0;

	ELA_ASSERT_INT_EQ(-1, ela_parse_u32(NULL, &v));
}

static void test_u32_null_value_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_parse_u32("1", NULL));
}

static void test_u32_hex_valid(void)
{
	uint32_t v = 0;

	ELA_ASSERT_INT_EQ(0, ela_parse_u32("0xff", &v));
	ELA_ASSERT_INT_EQ(255, (int)v);
}

static void test_u32_overflow_returns_minus1(void)
{
	uint32_t v = 0;

	/* 4294967296 == 2^32 — one above UINT32_MAX */
	ELA_ASSERT_INT_EQ(-1, ela_parse_u32("4294967296", &v));
}

static void test_u32_negative_text_returns_minus1(void)
{
	uint32_t v = 0;

	ELA_ASSERT_INT_EQ(-1, ela_parse_u32("-1", &v));
}

/* =========================================================================
 * ela_parse_u64
 * ====================================================================== */

static void test_u64_null_text_returns_minus1(void)
{
	uint64_t v = 0;

	ELA_ASSERT_INT_EQ(-1, ela_parse_u64(NULL, &v));
}

static void test_u64_null_value_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_parse_u64("1", NULL));
}

static void test_u64_hex_with_trailing_whitespace_valid(void)
{
	uint64_t v = 0;

	ELA_ASSERT_INT_EQ(0, ela_parse_u64("0x1000 \n", &v));
	ELA_ASSERT_INT_EQ(4096, (int)v);
}

static void test_u64_non_numeric_returns_minus1(void)
{
	uint64_t v = 0;

	ELA_ASSERT_INT_EQ(-1, ela_parse_u64("abc", &v));
}

/* =========================================================================
 * ela_parse_bool_string
 * ====================================================================== */

static void test_bool_null_value_returns_false(void)
{
	const char *n = NULL;

	ELA_ASSERT_FALSE(ela_parse_bool_string(NULL, &n));
}

static void test_bool_null_normalized_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_parse_bool_string("true", NULL));
}

static void test_bool_truthy_values(void)
{
	const char *n = NULL;

	ELA_ASSERT_TRUE(ela_parse_bool_string("1", &n));
	ELA_ASSERT_STR_EQ("true", n);
	ELA_ASSERT_TRUE(ela_parse_bool_string("true", &n));
	ELA_ASSERT_STR_EQ("true", n);
	ELA_ASSERT_TRUE(ela_parse_bool_string("yes", &n));
	ELA_ASSERT_STR_EQ("true", n);
	ELA_ASSERT_TRUE(ela_parse_bool_string("on", &n));
	ELA_ASSERT_STR_EQ("true", n);
}

static void test_bool_falsy_values(void)
{
	const char *n = NULL;

	ELA_ASSERT_TRUE(ela_parse_bool_string("0", &n));
	ELA_ASSERT_STR_EQ("false", n);
	ELA_ASSERT_TRUE(ela_parse_bool_string("false", &n));
	ELA_ASSERT_STR_EQ("false", n);
	ELA_ASSERT_TRUE(ela_parse_bool_string("no", &n));
	ELA_ASSERT_STR_EQ("false", n);
	ELA_ASSERT_TRUE(ela_parse_bool_string("off", &n));
	ELA_ASSERT_STR_EQ("false", n);
}

static void test_bool_invalid_value_returns_false(void)
{
	const char *n = NULL;

	ELA_ASSERT_FALSE(ela_parse_bool_string("maybe", &n));
	ELA_ASSERT_FALSE(ela_parse_bool_string("", &n));
}

/* =========================================================================
 * ela_output_format_is_valid / ela_output_format_or_default
 * ====================================================================== */

static void test_format_valid_values(void)
{
	ELA_ASSERT_TRUE(ela_output_format_is_valid("txt"));
	ELA_ASSERT_TRUE(ela_output_format_is_valid("csv"));
	ELA_ASSERT_TRUE(ela_output_format_is_valid("json"));
}

static void test_format_invalid_values(void)
{
	ELA_ASSERT_FALSE(ela_output_format_is_valid(NULL));
	ELA_ASSERT_FALSE(ela_output_format_is_valid(""));
	ELA_ASSERT_FALSE(ela_output_format_is_valid("yaml"));
	ELA_ASSERT_FALSE(ela_output_format_is_valid("xml"));
}

static void test_format_or_default_null_falls_back(void)
{
	ELA_ASSERT_STR_EQ("txt", ela_output_format_or_default(NULL, "txt"));
}

static void test_format_or_default_empty_falls_back(void)
{
	ELA_ASSERT_STR_EQ("csv", ela_output_format_or_default("", "csv"));
}

static void test_format_or_default_valid_returns_as_is(void)
{
	ELA_ASSERT_STR_EQ("json", ela_output_format_or_default("json", "txt"));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_command_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* ela_parse_positive_size_arg */
		{ "size/null_spec",            test_size_null_spec_returns_minus1 },
		{ "size/null_out",             test_size_null_out_returns_minus1 },
		{ "size/empty",                test_size_empty_string_returns_minus1 },
		{ "size/zero",                 test_size_zero_returns_minus1 },
		{ "size/negative",             test_size_negative_returns_minus1 },
		{ "size/non_numeric",          test_size_non_numeric_returns_minus1 },
		{ "size/trailing_chars",       test_size_trailing_chars_returns_minus1 },
		{ "size/valid_decimal",        test_size_valid_decimal },
		{ "size/one_is_valid",         test_size_one_is_valid },
		/* ela_parse_u32 */
		{ "u32/null_text",             test_u32_null_text_returns_minus1 },
		{ "u32/null_value",            test_u32_null_value_returns_minus1 },
		{ "u32/hex_valid",             test_u32_hex_valid },
		{ "u32/overflow",              test_u32_overflow_returns_minus1 },
		{ "u32/negative_text",         test_u32_negative_text_returns_minus1 },
		/* ela_parse_u64 */
		{ "u64/null_text",             test_u64_null_text_returns_minus1 },
		{ "u64/null_value",            test_u64_null_value_returns_minus1 },
		{ "u64/hex_trailing_ws",       test_u64_hex_with_trailing_whitespace_valid },
		{ "u64/non_numeric",           test_u64_non_numeric_returns_minus1 },
		/* ela_parse_bool_string */
		{ "bool/null_value",           test_bool_null_value_returns_false },
		{ "bool/null_normalized",      test_bool_null_normalized_returns_false },
		{ "bool/truthy_values",        test_bool_truthy_values },
		{ "bool/falsy_values",         test_bool_falsy_values },
		{ "bool/invalid",              test_bool_invalid_value_returns_false },
		/* ela_output_format_is_valid / or_default */
		{ "format/valid",              test_format_valid_values },
		{ "format/invalid",            test_format_invalid_values },
		{ "format/or_default_null",    test_format_or_default_null_falls_back },
		{ "format/or_default_empty",   test_format_or_default_empty_falls_back },
		{ "format/or_default_present", test_format_or_default_valid_returns_as_is },
	};

	return ela_run_test_suite("command_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
