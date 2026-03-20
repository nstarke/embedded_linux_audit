// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ela_conf.h"
#include "../../../agent/net/ela_conf_util.h"

#include <string.h>

/* =========================================================================
 * ela_conf_trim_right
 * ====================================================================== */

static void test_trim_null_no_crash(void)
{
	ela_conf_trim_right(NULL); /* must not crash */
	ELA_ASSERT_TRUE(1);
}

static void test_trim_trailing_crlf(void)
{
	char line[] = "output-format=json \r\n";

	ela_conf_trim_right(line);
	ELA_ASSERT_STR_EQ("output-format=json", line);
}

static void test_trim_trailing_spaces_and_tabs(void)
{
	char line[] = "key=val \t  ";

	ela_conf_trim_right(line);
	ELA_ASSERT_STR_EQ("key=val", line);
}

static void test_trim_already_clean_unchanged(void)
{
	char line[] = "key=value";

	ela_conf_trim_right(line);
	ELA_ASSERT_STR_EQ("key=value", line);
}

static void test_trim_all_whitespace_becomes_empty(void)
{
	char line[] = "   \t\r\n";

	ela_conf_trim_right(line);
	ELA_ASSERT_STR_EQ("", line);
}

/* =========================================================================
 * ela_conf_apply_line
 * ====================================================================== */

static void test_apply_null_conf_no_crash(void)
{
	ela_conf_apply_line(NULL, "remote=ws://host/ws"); /* must not crash */
	ELA_ASSERT_TRUE(1);
}

static void test_apply_null_line_no_crash(void)
{
	struct ela_conf conf;

	memset(&conf, 0, sizeof(conf));
	ela_conf_apply_line(&conf, NULL); /* must not crash */
	ELA_ASSERT_TRUE(1);
}

static void test_apply_comment_ignored(void)
{
	struct ela_conf conf;

	memset(&conf, 0, sizeof(conf));
	ela_conf_apply_line(&conf, "# remote=ws://host/ws");
	ELA_ASSERT_INT_EQ('\0', conf.remote[0]);
}

static void test_apply_no_equals_ignored(void)
{
	struct ela_conf conf;

	memset(&conf, 0, sizeof(conf));
	ela_conf_apply_line(&conf, "remotews://host/ws");
	ELA_ASSERT_INT_EQ('\0', conf.remote[0]);
}

static void test_apply_unknown_key_ignored(void)
{
	struct ela_conf conf;

	memset(&conf, 0, sizeof(conf));
	ela_conf_apply_line(&conf, "unknown-key=something");
	/* None of the known fields should be set */
	ELA_ASSERT_INT_EQ('\0', conf.remote[0]);
	ELA_ASSERT_INT_EQ('\0', conf.output_http[0]);
	ELA_ASSERT_INT_EQ('\0', conf.output_format[0]);
	ELA_ASSERT_INT_EQ(0, conf.insecure);
}

static void test_apply_all_known_fields(void)
{
	struct ela_conf conf;

	memset(&conf, 0, sizeof(conf));
	ela_conf_apply_line(&conf, "remote=ws://agent.example/ws");
	ela_conf_apply_line(&conf, "output-http=https://ela.example/upload");
	ela_conf_apply_line(&conf, "output-format=json");
	ela_conf_apply_line(&conf, "insecure=true");

	ELA_ASSERT_STR_EQ("ws://agent.example/ws", conf.remote);
	ELA_ASSERT_STR_EQ("https://ela.example/upload", conf.output_http);
	ELA_ASSERT_STR_EQ("json", conf.output_format);
	ELA_ASSERT_INT_EQ(1, conf.insecure);
}

static void test_apply_insecure_false_sets_zero(void)
{
	struct ela_conf conf;

	memset(&conf, 0, sizeof(conf));
	conf.insecure = 1; /* pre-set to ensure it's actively cleared */
	ela_conf_apply_line(&conf, "insecure=false");
	ELA_ASSERT_INT_EQ(0, conf.insecure);
}

static void test_apply_insecure_one_sets_one(void)
{
	struct ela_conf conf;

	memset(&conf, 0, sizeof(conf));
	ela_conf_apply_line(&conf, "insecure=1");
	ELA_ASSERT_INT_EQ(1, conf.insecure);
}

static void test_apply_insecure_zero_sets_zero(void)
{
	struct ela_conf conf;

	memset(&conf, 0, sizeof(conf));
	conf.insecure = 1;
	ela_conf_apply_line(&conf, "insecure=0");
	ELA_ASSERT_INT_EQ(0, conf.insecure);
}

/* =========================================================================
 * ela_conf_string_is_true
 * ====================================================================== */

static void test_string_is_true_true_value(void)
{
	ELA_ASSERT_TRUE(ela_conf_string_is_true("true"));
}

static void test_string_is_true_one_value(void)
{
	ELA_ASSERT_TRUE(ela_conf_string_is_true("1"));
}

static void test_string_is_true_false_value(void)
{
	ELA_ASSERT_FALSE(ela_conf_string_is_true("false"));
}

static void test_string_is_true_zero_value(void)
{
	ELA_ASSERT_FALSE(ela_conf_string_is_true("0"));
}

static void test_string_is_true_null_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_conf_string_is_true(NULL));
}

static void test_string_is_true_yes_not_accepted(void)
{
	/* only "true" and "1" are accepted — "yes" is not */
	ELA_ASSERT_FALSE(ela_conf_string_is_true("yes"));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_ela_conf_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* ela_conf_trim_right */
		{ "trim/null_no_crash",           test_trim_null_no_crash },
		{ "trim/trailing_crlf",           test_trim_trailing_crlf },
		{ "trim/trailing_spaces_tabs",    test_trim_trailing_spaces_and_tabs },
		{ "trim/already_clean",           test_trim_already_clean_unchanged },
		{ "trim/all_whitespace",          test_trim_all_whitespace_becomes_empty },
		/* ela_conf_apply_line */
		{ "apply/null_conf_no_crash",     test_apply_null_conf_no_crash },
		{ "apply/null_line_no_crash",     test_apply_null_line_no_crash },
		{ "apply/comment_ignored",        test_apply_comment_ignored },
		{ "apply/no_equals_ignored",      test_apply_no_equals_ignored },
		{ "apply/unknown_key_ignored",    test_apply_unknown_key_ignored },
		{ "apply/all_known_fields",       test_apply_all_known_fields },
		{ "apply/insecure_false",         test_apply_insecure_false_sets_zero },
		{ "apply/insecure_1",             test_apply_insecure_one_sets_one },
		{ "apply/insecure_0",             test_apply_insecure_zero_sets_zero },
		/* ela_conf_string_is_true */
		{ "string_is_true/true",          test_string_is_true_true_value },
		{ "string_is_true/1",             test_string_is_true_one_value },
		{ "string_is_true/false",         test_string_is_true_false_value },
		{ "string_is_true/0",             test_string_is_true_zero_value },
		{ "string_is_true/null",          test_string_is_true_null_returns_false },
		{ "string_is_true/yes_rejected",  test_string_is_true_yes_not_accepted },
	};

	return ela_run_test_suite("ela_conf_util", cases, sizeof(cases) / sizeof(cases[0]));
}
