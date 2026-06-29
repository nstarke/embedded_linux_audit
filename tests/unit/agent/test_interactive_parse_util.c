// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/interactive_parse_util.h"

#include <fcntl.h>
#include <unistd.h>

static void test_interactive_parse_line_handles_quotes_escapes_and_comments(void)
{
	char **argv = NULL;
	int argc = 0;

	ELA_ASSERT_INT_EQ(0, interactive_parse_line("linux execute-command \"echo hi\" 'a b' plain\\ value # trailing",
						       &argv, &argc));
	ELA_ASSERT_INT_EQ(5, argc);
	ELA_ASSERT_STR_EQ("linux", argv[0]);
	ELA_ASSERT_STR_EQ("execute-command", argv[1]);
	ELA_ASSERT_STR_EQ("echo hi", argv[2]);
	ELA_ASSERT_STR_EQ("a b", argv[3]);
	ELA_ASSERT_STR_EQ("plain value", argv[4]);
	interactive_free_argv(argv, argc);
}

static void test_interactive_parse_line_skips_blank_and_comment_lines(void)
{
	char **argv = NULL;
	int argc = -1;

	ELA_ASSERT_INT_EQ(0, interactive_parse_line("   # comment only", &argv, &argc));
	ELA_ASSERT_INT_EQ(0, argc);
	ELA_ASSERT_TRUE(argv == NULL);
}

static void test_interactive_parse_line_rejects_unterminated_quotes(void)
{
	char **argv = NULL;
	int argc = 0;
	int saved_stderr = dup(STDERR_FILENO);
	int null_fd;

	ELA_ASSERT_TRUE(saved_stderr >= 0);
	null_fd = open("/dev/null", O_WRONLY);
	ELA_ASSERT_TRUE(null_fd >= 0);
	ELA_ASSERT_TRUE(dup2(null_fd, STDERR_FILENO) >= 0);
	close(null_fd);

	ELA_ASSERT_INT_EQ(2, interactive_parse_line("linux execute-command \"unterminated", &argv, &argc));
	ELA_ASSERT_TRUE(dup2(saved_stderr, STDERR_FILENO) >= 0);
	close(saved_stderr);
	ELA_ASSERT_TRUE(argv == NULL);
}

static void test_interactive_parse_line_rejects_null_outputs(void)
{
	char **argv = NULL;
	int argc = 0;

	ELA_ASSERT_INT_EQ(-1, interactive_parse_line("cmd", NULL, &argc));
	ELA_ASSERT_INT_EQ(-1, interactive_parse_line("cmd", &argv, NULL));
}

/*
 * An empty quoted token ("") never appends a character to the per-arg buffer,
 * so the parser falls through to interactive_append_arg() — the only code path
 * that reaches it.  This pins that path under coverage and documents the
 * current behavior: the raw quote characters are preserved as the argument.
 */
static void test_interactive_parse_line_empty_quoted_token(void)
{
	char **argv = NULL;
	int argc = 0;

	ELA_ASSERT_INT_EQ(0, interactive_parse_line("cmd \"\"", &argv, &argc));
	ELA_ASSERT_INT_EQ(2, argc);
	ELA_ASSERT_STR_EQ("cmd", argv[0]);
	ELA_ASSERT_STR_EQ("\"\"", argv[1]);
	ELA_ASSERT_TRUE(argv[2] == NULL);
	interactive_free_argv(argv, argc);
}

int run_interactive_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "interactive_parse_line_handles_quotes_escapes_and_comments", test_interactive_parse_line_handles_quotes_escapes_and_comments },
		{ "interactive_parse_line_skips_blank_and_comment_lines", test_interactive_parse_line_skips_blank_and_comment_lines },
		{ "interactive_parse_line_rejects_unterminated_quotes", test_interactive_parse_line_rejects_unterminated_quotes },
		{ "interactive_parse_line_rejects_null_outputs", test_interactive_parse_line_rejects_null_outputs },
		{ "interactive_parse_line_empty_quoted_token", test_interactive_parse_line_empty_quoted_token },
	};

	return ela_run_test_suite("interactive_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
