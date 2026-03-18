// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/tpm2_command_util.h"

static void test_tpm2_supported_commands_include_expected_entries(void)
{
	size_t count = 0;
	const struct ela_tpm2_command_desc *commands = ela_tpm2_supported_commands(&count);

	ELA_ASSERT_TRUE(commands != NULL);
	ELA_ASSERT_INT_EQ(4, count);
	ELA_ASSERT_STR_EQ("createprimary", commands[0].name);
	ELA_ASSERT_STR_EQ("pcrread", commands[3].name);
}

static void test_tpm2_help_and_lookup_helpers_classify_tokens(void)
{
	ELA_ASSERT_TRUE(ela_tpm2_is_help_token("help"));
	ELA_ASSERT_TRUE(ela_tpm2_is_help_token("--help"));
	ELA_ASSERT_FALSE(ela_tpm2_is_help_token("getcap"));

	ELA_ASSERT_INT_EQ(1, ela_tpm2_find_command_index("getcap"));
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_find_command_index("bogus"));
}

int run_tpm2_command_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "tpm2_supported_commands_include_expected_entries", test_tpm2_supported_commands_include_expected_entries },
		{ "tpm2_help_and_lookup_helpers_classify_tokens", test_tpm2_help_and_lookup_helpers_classify_tokens },
	};

	return ela_run_test_suite("tpm2_command_util", cases, sizeof(cases) / sizeof(cases[0]));
}
