// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/command_parse_util.h"

static void test_parse_positive_size_arg_accepts_valid_decimal(void)
{
	size_t value = 0;

	ELA_ASSERT_INT_EQ(0, ela_parse_positive_size_arg("42", &value));
	ELA_ASSERT_INT_EQ(42, value);
}

static void test_parse_positive_size_arg_rejects_invalid_values(void)
{
	size_t value = 0;

	ELA_ASSERT_INT_EQ(-1, ela_parse_positive_size_arg("0", &value));
	ELA_ASSERT_INT_EQ(-1, ela_parse_positive_size_arg("-1", &value));
	ELA_ASSERT_INT_EQ(-1, ela_parse_positive_size_arg("abc", &value));
}

static void test_output_format_helpers_validate_and_default(void)
{
	ELA_ASSERT_TRUE(ela_output_format_is_valid("txt"));
	ELA_ASSERT_TRUE(ela_output_format_is_valid("csv"));
	ELA_ASSERT_TRUE(ela_output_format_is_valid("json"));
	ELA_ASSERT_FALSE(ela_output_format_is_valid("yaml"));
	ELA_ASSERT_STR_EQ("txt", ela_output_format_or_default(NULL, "txt"));
	ELA_ASSERT_STR_EQ("json", ela_output_format_or_default("json", "txt"));
}

static void test_unsigned_integer_helpers_accept_valid_values(void)
{
	uint32_t value32 = 0;
	uint64_t value64 = 0;

	ELA_ASSERT_INT_EQ(0, ela_parse_u32("0xff", &value32));
	ELA_ASSERT_INT_EQ(255, value32);
	ELA_ASSERT_INT_EQ(0, ela_parse_u64("0x1000 \n", &value64));
	ELA_ASSERT_INT_EQ(4096, value64);
}

static void test_unsigned_integer_helpers_reject_invalid_values(void)
{
	uint32_t value32 = 0;
	uint64_t value64 = 0;

	ELA_ASSERT_INT_EQ(-1, ela_parse_u32("-1", &value32));
	ELA_ASSERT_INT_EQ(-1, ela_parse_u32("4294967296", &value32));
	ELA_ASSERT_INT_EQ(-1, ela_parse_u64("abc", &value64));
}

static void test_parse_bool_string_normalizes_common_values(void)
{
	const char *normalized = NULL;

	ELA_ASSERT_TRUE(ela_parse_bool_string("yes", &normalized));
	ELA_ASSERT_STR_EQ("true", normalized);
	ELA_ASSERT_TRUE(ela_parse_bool_string("0", &normalized));
	ELA_ASSERT_STR_EQ("false", normalized);
	ELA_ASSERT_FALSE(ela_parse_bool_string("maybe", &normalized));
}

int run_command_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "parse_positive_size_arg_accepts_valid_decimal", test_parse_positive_size_arg_accepts_valid_decimal },
		{ "parse_positive_size_arg_rejects_invalid_values", test_parse_positive_size_arg_rejects_invalid_values },
		{ "output_format_helpers_validate_and_default", test_output_format_helpers_validate_and_default },
		{ "unsigned_integer_helpers_accept_valid_values", test_unsigned_integer_helpers_accept_valid_values },
		{ "unsigned_integer_helpers_reject_invalid_values", test_unsigned_integer_helpers_reject_invalid_values },
		{ "parse_bool_string_normalizes_common_values", test_parse_bool_string_normalizes_common_values },
	};

	return ela_run_test_suite("command_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
