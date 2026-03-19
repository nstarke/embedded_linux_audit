// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/tpm2_command_util.h"

#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * ela_tpm2_supported_commands
 * ---------------------------------------------------------------------- */

static void test_supported_commands_count(void)
{
	size_t count = 0;
	const struct ela_tpm2_command_desc *cmds = ela_tpm2_supported_commands(&count);

	ELA_ASSERT_TRUE(cmds != NULL);
	ELA_ASSERT_INT_EQ(4, (int)count);
}

static void test_supported_commands_null_count_out(void)
{
	/* Must not crash with NULL count_out */
	const struct ela_tpm2_command_desc *cmds = ela_tpm2_supported_commands(NULL);

	ELA_ASSERT_TRUE(cmds != NULL);
}

static void test_supported_commands_names(void)
{
	size_t count = 0;
	const struct ela_tpm2_command_desc *cmds = ela_tpm2_supported_commands(&count);

	ELA_ASSERT_STR_EQ("createprimary", cmds[0].name);
	ELA_ASSERT_STR_EQ("getcap",        cmds[1].name);
	ELA_ASSERT_STR_EQ("nvreadpublic",  cmds[2].name);
	ELA_ASSERT_STR_EQ("pcrread",       cmds[3].name);
}

static void test_supported_commands_summaries_non_empty(void)
{
	size_t count = 0;
	const struct ela_tpm2_command_desc *cmds = ela_tpm2_supported_commands(&count);
	size_t i;

	for (i = 0; i < count; i++) {
		ELA_ASSERT_TRUE(cmds[i].summary != NULL);
		ELA_ASSERT_TRUE(cmds[i].summary[0] != '\0');
	}
}

/* -------------------------------------------------------------------------
 * ela_tpm2_is_help_token
 * ---------------------------------------------------------------------- */

static void test_is_help_token_all_forms(void)
{
	ELA_ASSERT_TRUE(ela_tpm2_is_help_token("help"));
	ELA_ASSERT_TRUE(ela_tpm2_is_help_token("--help"));
	ELA_ASSERT_TRUE(ela_tpm2_is_help_token("-h"));
}

static void test_is_help_token_null_and_empty(void)
{
	ELA_ASSERT_FALSE(ela_tpm2_is_help_token(NULL));
	ELA_ASSERT_FALSE(ela_tpm2_is_help_token(""));
}

static void test_is_help_token_non_help(void)
{
	ELA_ASSERT_FALSE(ela_tpm2_is_help_token("getcap"));
	ELA_ASSERT_FALSE(ela_tpm2_is_help_token("pcrread"));
	ELA_ASSERT_FALSE(ela_tpm2_is_help_token("HELP"));
	ELA_ASSERT_FALSE(ela_tpm2_is_help_token("Help"));
	ELA_ASSERT_FALSE(ela_tpm2_is_help_token("-help"));
}

/* -------------------------------------------------------------------------
 * ela_tpm2_find_command_index
 * ---------------------------------------------------------------------- */

static void test_find_command_index_all_known(void)
{
	ELA_ASSERT_INT_EQ(0, ela_tpm2_find_command_index("createprimary"));
	ELA_ASSERT_INT_EQ(1, ela_tpm2_find_command_index("getcap"));
	ELA_ASSERT_INT_EQ(2, ela_tpm2_find_command_index("nvreadpublic"));
	ELA_ASSERT_INT_EQ(3, ela_tpm2_find_command_index("pcrread"));
}

static void test_find_command_index_null_and_empty(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_find_command_index(NULL));
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_find_command_index(""));
}

static void test_find_command_index_unknown(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_find_command_index("bogus"));
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_find_command_index("GETCAP"));
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_find_command_index("list-commands"));
}

/* -------------------------------------------------------------------------
 * ela_tpm2_parse_hierarchy
 * ---------------------------------------------------------------------- */

static void test_parse_hierarchy_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_parse_hierarchy("o", NULL));
}

static void test_parse_hierarchy_null_name_is_null_hierarchy(void)
{
	uint32_t out = 0;

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_hierarchy(NULL, &out));
	ELA_ASSERT_INT_EQ((int)ELA_TPM2_RH_NULL, (int)out);
}

static void test_parse_hierarchy_owner(void)
{
	uint32_t out = 0;

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_hierarchy("o", &out));
	ELA_ASSERT_INT_EQ((int)ELA_TPM2_RH_OWNER, (int)out);

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_hierarchy("owner", &out));
	ELA_ASSERT_INT_EQ((int)ELA_TPM2_RH_OWNER, (int)out);
}

static void test_parse_hierarchy_platform(void)
{
	uint32_t out = 0;

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_hierarchy("p", &out));
	ELA_ASSERT_INT_EQ((int)ELA_TPM2_RH_PLATFORM, (int)out);

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_hierarchy("platform", &out));
	ELA_ASSERT_INT_EQ((int)ELA_TPM2_RH_PLATFORM, (int)out);
}

static void test_parse_hierarchy_endorsement(void)
{
	uint32_t out = 0;

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_hierarchy("e", &out));
	ELA_ASSERT_INT_EQ((int)ELA_TPM2_RH_ENDORSEMENT, (int)out);

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_hierarchy("endorsement", &out));
	ELA_ASSERT_INT_EQ((int)ELA_TPM2_RH_ENDORSEMENT, (int)out);
}

static void test_parse_hierarchy_null_hierarchy(void)
{
	uint32_t out = 0;

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_hierarchy("n", &out));
	ELA_ASSERT_INT_EQ((int)ELA_TPM2_RH_NULL, (int)out);

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_hierarchy("null", &out));
	ELA_ASSERT_INT_EQ((int)ELA_TPM2_RH_NULL, (int)out);
}

static void test_parse_hierarchy_unknown(void)
{
	uint32_t out = 0;

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_parse_hierarchy("x", &out));
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_parse_hierarchy("Owner", &out));
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_parse_hierarchy("", &out));
}

static void test_parse_hierarchy_constants_have_correct_values(void)
{
	/* Verify the ELA constants match the TPM2 spec handle values */
	ELA_ASSERT_INT_EQ((int)0x40000001u, (int)ELA_TPM2_RH_OWNER);
	ELA_ASSERT_INT_EQ((int)0x4000000Cu, (int)ELA_TPM2_RH_PLATFORM);
	ELA_ASSERT_INT_EQ((int)0x4000000Bu, (int)ELA_TPM2_RH_ENDORSEMENT);
	ELA_ASSERT_INT_EQ((int)0x40000007u, (int)ELA_TPM2_RH_NULL);
}

int run_tpm2_command_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* supported_commands */
		{ "supported_commands_count",                test_supported_commands_count },
		{ "supported_commands_null_count_out",       test_supported_commands_null_count_out },
		{ "supported_commands_names",                test_supported_commands_names },
		{ "supported_commands_summaries_non_empty",  test_supported_commands_summaries_non_empty },
		/* is_help_token */
		{ "is_help_token_all_forms",                 test_is_help_token_all_forms },
		{ "is_help_token_null_and_empty",            test_is_help_token_null_and_empty },
		{ "is_help_token_non_help",                  test_is_help_token_non_help },
		/* find_command_index */
		{ "find_command_index_all_known",            test_find_command_index_all_known },
		{ "find_command_index_null_and_empty",       test_find_command_index_null_and_empty },
		{ "find_command_index_unknown",              test_find_command_index_unknown },
		/* parse_hierarchy */
		{ "parse_hierarchy_null_out",                test_parse_hierarchy_null_out },
		{ "parse_hierarchy_null_name",               test_parse_hierarchy_null_name_is_null_hierarchy },
		{ "parse_hierarchy_owner",                   test_parse_hierarchy_owner },
		{ "parse_hierarchy_platform",                test_parse_hierarchy_platform },
		{ "parse_hierarchy_endorsement",             test_parse_hierarchy_endorsement },
		{ "parse_hierarchy_null_hierarchy",          test_parse_hierarchy_null_hierarchy },
		{ "parse_hierarchy_unknown",                 test_parse_hierarchy_unknown },
		{ "parse_hierarchy_constants_correct",       test_parse_hierarchy_constants_have_correct_values },
	};

	return ela_run_test_suite("tpm2_command_util", cases, sizeof(cases) / sizeof(cases[0]));
}
