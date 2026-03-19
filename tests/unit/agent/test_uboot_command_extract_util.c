// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/image/uboot_command_extract_util.h"

static void test_uboot_command_name_heuristics_filter_candidates(void)
{
	ELA_ASSERT_TRUE(ela_uboot_is_printable_ascii('A'));
	ELA_ASSERT_FALSE(ela_uboot_is_printable_ascii('\n'));

	ELA_ASSERT_TRUE(ela_uboot_token_looks_like_command_name("bootm"));
	ELA_ASSERT_TRUE(ela_uboot_token_looks_like_command_name("save_env"));
	ELA_ASSERT_FALSE(ela_uboot_token_looks_like_command_name("1bad"));
	ELA_ASSERT_FALSE(ela_uboot_token_looks_like_command_name("bad token"));
}

static void test_uboot_extract_commands_from_blob_scores_and_sorts_results(void)
{
	static const uint8_t blob[] =
		"List of commands\0"
		"bootm\0"
		"bootm\0"
		"help\0"
		"printenv\0";
	struct extracted_command *cmds = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(0, ela_uboot_extract_commands_from_blob(blob, sizeof(blob) - 1, &cmds, &count));
	ELA_ASSERT_TRUE(count >= 1);
	ELA_ASSERT_STR_EQ("bootm", cmds[0].name);
	ela_uboot_free_extracted_commands(cmds, count);
}

int run_uboot_command_extract_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "uboot_command_name_heuristics_filter_candidates", test_uboot_command_name_heuristics_filter_candidates },
		{ "uboot_extract_commands_from_blob_scores_and_sorts_results", test_uboot_extract_commands_from_blob_scores_and_sorts_results },
	};

	return ela_run_test_suite("uboot_command_extract_util", cases, sizeof(cases) / sizeof(cases[0]));
}
