// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/image/uboot_command_extract_util.h"

#include <stdint.h>
#include <string.h>

/* =========================================================================
 * ela_uboot_is_printable_ascii
 * ====================================================================== */

static void test_printable_space(void)
{
	ELA_ASSERT_TRUE(ela_uboot_is_printable_ascii(0x20)); /* space */
}

static void test_printable_tilde(void)
{
	ELA_ASSERT_TRUE(ela_uboot_is_printable_ascii(0x7e)); /* ~ */
}

static void test_printable_letter(void)
{
	ELA_ASSERT_TRUE(ela_uboot_is_printable_ascii('A'));
}

static void test_printable_digit(void)
{
	ELA_ASSERT_TRUE(ela_uboot_is_printable_ascii('5'));
}

static void test_printable_below_space(void)
{
	ELA_ASSERT_FALSE(ela_uboot_is_printable_ascii(0x1f));
}

static void test_printable_del(void)
{
	ELA_ASSERT_FALSE(ela_uboot_is_printable_ascii(0x7f)); /* DEL */
}

static void test_printable_nul(void)
{
	ELA_ASSERT_FALSE(ela_uboot_is_printable_ascii(0x00));
}

/* =========================================================================
 * ela_uboot_token_looks_like_command_name
 * ====================================================================== */

static void test_cmd_name_null(void)
{
	ELA_ASSERT_FALSE(ela_uboot_token_looks_like_command_name(NULL));
}

static void test_cmd_name_empty(void)
{
	ELA_ASSERT_FALSE(ela_uboot_token_looks_like_command_name(""));
}

static void test_cmd_name_one_char(void)
{
	ELA_ASSERT_FALSE(ela_uboot_token_looks_like_command_name("a"));
}

static void test_cmd_name_two_chars(void)
{
	ELA_ASSERT_TRUE(ela_uboot_token_looks_like_command_name("md"));
}

static void test_cmd_name_starts_with_digit(void)
{
	ELA_ASSERT_FALSE(ela_uboot_token_looks_like_command_name("1bad"));
}

static void test_cmd_name_starts_with_dash(void)
{
	ELA_ASSERT_FALSE(ela_uboot_token_looks_like_command_name("-bad"));
}

static void test_cmd_name_no_alpha(void)
{
	ELA_ASSERT_FALSE(ela_uboot_token_looks_like_command_name("12345"));
}

static void test_cmd_name_space_inside(void)
{
	ELA_ASSERT_FALSE(ela_uboot_token_looks_like_command_name("bad name"));
}

static void test_cmd_name_invalid_char(void)
{
	ELA_ASSERT_FALSE(ela_uboot_token_looks_like_command_name("bad@name"));
}

static void test_cmd_name_simple_valid(void)
{
	ELA_ASSERT_TRUE(ela_uboot_token_looks_like_command_name("bootm"));
}

static void test_cmd_name_with_underscore(void)
{
	ELA_ASSERT_TRUE(ela_uboot_token_looks_like_command_name("save_env"));
}

static void test_cmd_name_with_dash(void)
{
	ELA_ASSERT_TRUE(ela_uboot_token_looks_like_command_name("fat-ls"));
}

static void test_cmd_name_with_dot(void)
{
	ELA_ASSERT_TRUE(ela_uboot_token_looks_like_command_name("fs.ls"));
}

static void test_cmd_name_exactly_32_chars(void)
{
	/* 32 lowercase letters — exactly at the limit */
	ELA_ASSERT_TRUE(ela_uboot_token_looks_like_command_name(
		"abcdefghijklmnopqrstuvwxyzabcdef"));
}

static void test_cmd_name_33_chars_too_long(void)
{
	ELA_ASSERT_FALSE(ela_uboot_token_looks_like_command_name(
		"abcdefghijklmnopqrstuvwxyzabcdefg"));
}

/* =========================================================================
 * ela_uboot_extracted_command_final_score
 * ====================================================================== */

static void test_score_null_cmd(void)
{
	ELA_ASSERT_INT_EQ(0, ela_uboot_extracted_command_final_score(NULL));
}

static void test_score_base_only(void)
{
	struct extracted_command c = { NULL, 1, 5, false, false };
	ELA_ASSERT_INT_EQ(5, ela_uboot_extracted_command_final_score(&c));
}

static void test_score_known_adds_2(void)
{
	struct extracted_command c = { NULL, 1, 5, true, false };
	ELA_ASSERT_INT_EQ(7, ela_uboot_extracted_command_final_score(&c));
}

static void test_score_context_adds_1(void)
{
	struct extracted_command c = { NULL, 1, 5, false, true };
	ELA_ASSERT_INT_EQ(6, ela_uboot_extracted_command_final_score(&c));
}

static void test_score_hits_2_adds_1(void)
{
	struct extracted_command c = { NULL, 2, 5, false, false };
	ELA_ASSERT_INT_EQ(6, ela_uboot_extracted_command_final_score(&c));
}

static void test_score_hits_4_adds_3(void)
{
	/* extra = 4-1=3, capped at 3 */
	struct extracted_command c = { NULL, 4, 5, false, false };
	ELA_ASSERT_INT_EQ(8, ela_uboot_extracted_command_final_score(&c));
}

static void test_score_hits_10_still_capped_at_3(void)
{
	struct extracted_command c = { NULL, 10, 5, false, false };
	ELA_ASSERT_INT_EQ(8, ela_uboot_extracted_command_final_score(&c));
}

static void test_score_combined(void)
{
	/* base=5 + known(2) + context(1) + hits=4→extra=3 = 11 */
	struct extracted_command c = { NULL, 4, 5, true, true };
	ELA_ASSERT_INT_EQ(11, ela_uboot_extracted_command_final_score(&c));
}

/* =========================================================================
 * ela_uboot_confidence_from_score
 * ====================================================================== */

static void test_confidence_negative(void)
{
	ELA_ASSERT_STR_EQ("low", ela_uboot_confidence_from_score(-1));
}

static void test_confidence_zero(void)
{
	ELA_ASSERT_STR_EQ("low", ela_uboot_confidence_from_score(0));
}

static void test_confidence_six(void)
{
	ELA_ASSERT_STR_EQ("low", ela_uboot_confidence_from_score(6));
}

static void test_confidence_seven(void)
{
	ELA_ASSERT_STR_EQ("medium", ela_uboot_confidence_from_score(7));
}

static void test_confidence_nine(void)
{
	ELA_ASSERT_STR_EQ("medium", ela_uboot_confidence_from_score(9));
}

static void test_confidence_ten(void)
{
	ELA_ASSERT_STR_EQ("high", ela_uboot_confidence_from_score(10));
}

static void test_confidence_large(void)
{
	ELA_ASSERT_STR_EQ("high", ela_uboot_confidence_from_score(100));
}

/* =========================================================================
 * ela_uboot_extract_commands_from_blob
 * ====================================================================== */

static void test_extract_null_blob(void)
{
	struct extracted_command *cmds = NULL;
	size_t count = 0;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_extract_commands_from_blob(
		NULL, 10, &cmds, &count));
}

static void test_extract_null_out_cmds(void)
{
	static const uint8_t blob[] = "bootm";
	size_t count = 0;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_extract_commands_from_blob(
		blob, sizeof(blob) - 1, NULL, &count));
}

static void test_extract_null_out_count(void)
{
	static const uint8_t blob[] = "bootm";
	struct extracted_command *cmds = NULL;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_extract_commands_from_blob(
		blob, sizeof(blob) - 1, &cmds, NULL));
}

static void test_extract_zero_blob_len(void)
{
	static const uint8_t blob[] = "bootm";
	struct extracted_command *cmds = NULL;
	size_t count = 0;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_extract_commands_from_blob(
		blob, 0, &cmds, &count));
}

static void test_extract_no_printable_chars(void)
{
	/* blob of non-printable bytes produces no commands */
	static const uint8_t blob[16] = { 0x00, 0x01, 0x80, 0xff };
	struct extracted_command *cmds = NULL;
	size_t count = 0;
	ELA_ASSERT_INT_EQ(0, ela_uboot_extract_commands_from_blob(
		blob, sizeof(blob), &cmds, &count));
	ELA_ASSERT_INT_EQ(0, (int)count);
	ela_uboot_free_extracted_commands(cmds, count);
}

static void test_extract_stop_token_skipped(void)
{
	/* "firmware" and "image" are stop tokens — nothing should be extracted */
	static const uint8_t blob[] = "firmware\0image\0";
	struct extracted_command *cmds = NULL;
	size_t count = 0;
	ELA_ASSERT_INT_EQ(0, ela_uboot_extract_commands_from_blob(
		blob, sizeof(blob) - 1, &cmds, &count));
	ELA_ASSERT_INT_EQ(0, (int)count);
	ela_uboot_free_extracted_commands(cmds, count);
}

static void test_extract_known_command_found(void)
{
	static const uint8_t blob[] = "bootm";
	struct extracted_command *cmds = NULL;
	size_t count = 0;
	ELA_ASSERT_INT_EQ(0, ela_uboot_extract_commands_from_blob(
		blob, sizeof(blob) - 1, &cmds, &count));
	ELA_ASSERT_TRUE(count >= 1);
	ELA_ASSERT_STR_EQ("bootm", cmds[0].name);
	ela_uboot_free_extracted_commands(cmds, count);
}

static void test_extract_sorts_by_score(void)
{
	/*
	 * "List of commands" context + "bootm" twice → bootm gets high score.
	 * "help" once with context → also high score but bootm has 2 hits.
	 * "printenv" once with context → lower score than bootm.
	 * The highest-scored command should sort first.
	 */
	static const uint8_t blob[] =
		"List of commands\0"
		"bootm\0"
		"bootm\0"
		"help\0"
		"printenv\0";
	struct extracted_command *cmds = NULL;
	size_t count = 0;
	ELA_ASSERT_INT_EQ(0, ela_uboot_extract_commands_from_blob(
		blob, sizeof(blob) - 1, &cmds, &count));
	ELA_ASSERT_TRUE(count >= 1);
	ELA_ASSERT_STR_EQ("bootm", cmds[0].name);
	ela_uboot_free_extracted_commands(cmds, count);
}

/* =========================================================================
 * ela_uboot_free_extracted_commands
 * ====================================================================== */

static void test_free_null_safe(void)
{
	/* must not crash */
	ela_uboot_free_extracted_commands(NULL, 0);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_command_extract_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* is_printable_ascii */
		{ "printable/space",           test_printable_space },
		{ "printable/tilde",           test_printable_tilde },
		{ "printable/letter",          test_printable_letter },
		{ "printable/digit",           test_printable_digit },
		{ "printable/below_space",     test_printable_below_space },
		{ "printable/del",             test_printable_del },
		{ "printable/nul",             test_printable_nul },
		/* token_looks_like_command_name */
		{ "cmd_name/null",             test_cmd_name_null },
		{ "cmd_name/empty",            test_cmd_name_empty },
		{ "cmd_name/one_char",         test_cmd_name_one_char },
		{ "cmd_name/two_chars",        test_cmd_name_two_chars },
		{ "cmd_name/starts_digit",     test_cmd_name_starts_with_digit },
		{ "cmd_name/starts_dash",      test_cmd_name_starts_with_dash },
		{ "cmd_name/no_alpha",         test_cmd_name_no_alpha },
		{ "cmd_name/space_inside",     test_cmd_name_space_inside },
		{ "cmd_name/invalid_char",     test_cmd_name_invalid_char },
		{ "cmd_name/simple_valid",     test_cmd_name_simple_valid },
		{ "cmd_name/underscore",       test_cmd_name_with_underscore },
		{ "cmd_name/dash",             test_cmd_name_with_dash },
		{ "cmd_name/dot",              test_cmd_name_with_dot },
		{ "cmd_name/exactly_32",       test_cmd_name_exactly_32_chars },
		{ "cmd_name/33_too_long",      test_cmd_name_33_chars_too_long },
		/* extracted_command_final_score */
		{ "score/null_cmd",            test_score_null_cmd },
		{ "score/base_only",           test_score_base_only },
		{ "score/known_adds_2",        test_score_known_adds_2 },
		{ "score/context_adds_1",      test_score_context_adds_1 },
		{ "score/hits_2_adds_1",       test_score_hits_2_adds_1 },
		{ "score/hits_4_adds_3",       test_score_hits_4_adds_3 },
		{ "score/hits_10_capped",      test_score_hits_10_still_capped_at_3 },
		{ "score/combined",            test_score_combined },
		/* confidence_from_score */
		{ "confidence/negative",       test_confidence_negative },
		{ "confidence/zero",           test_confidence_zero },
		{ "confidence/six",            test_confidence_six },
		{ "confidence/seven",          test_confidence_seven },
		{ "confidence/nine",           test_confidence_nine },
		{ "confidence/ten",            test_confidence_ten },
		{ "confidence/large",          test_confidence_large },
		/* extract_commands_from_blob */
		{ "extract/null_blob",         test_extract_null_blob },
		{ "extract/null_out_cmds",     test_extract_null_out_cmds },
		{ "extract/null_out_count",    test_extract_null_out_count },
		{ "extract/zero_blob_len",     test_extract_zero_blob_len },
		{ "extract/no_printable",      test_extract_no_printable_chars },
		{ "extract/stop_token",        test_extract_stop_token_skipped },
		{ "extract/known_found",       test_extract_known_command_found },
		{ "extract/sorted_by_score",   test_extract_sorts_by_score },
		/* free */
		{ "free/null_safe",            test_free_null_safe },
	};
	return ela_run_test_suite("uboot_command_extract_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
