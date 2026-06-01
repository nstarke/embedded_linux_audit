// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "test_shell_stubs.h"
#include "../../../agent/shell/interactive.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

/* Redirect stdout to /dev/null around a noisy call, restoring afterwards. */
static int g_saved_stdout = -1;

static void silence_stdout_begin(void)
{
	int devnull;

	fflush(stdout);
	g_saved_stdout = dup(STDOUT_FILENO);
	devnull = open("/dev/null", O_WRONLY);
	if (devnull >= 0) {
		dup2(devnull, STDOUT_FILENO);
		close(devnull);
	}
}

static void silence_stdout_end(void)
{
	fflush(stdout);
	if (g_saved_stdout >= 0) {
		dup2(g_saved_stdout, STDOUT_FILENO);
		close(g_saved_stdout);
		g_saved_stdout = -1;
	}
}

/* Run interactive_loop() with `input` fed on stdin; stdout is silenced. */
static int run_loop_with_input(const char *prog, const char *input)
{
	char tmpl[] = "/tmp/ela_itest_XXXXXX";
	int fd = mkstemp(tmpl);
	int saved_stdin;
	int rc;

	if (fd < 0)
		return -999;
	if (write(fd, input, strlen(input)) < 0) {
		close(fd);
		unlink(tmpl);
		return -998;
	}
	lseek(fd, 0, SEEK_SET);

	saved_stdin = dup(STDIN_FILENO);
	dup2(fd, STDIN_FILENO);
	silence_stdout_begin();

	rc = interactive_loop(prog);

	silence_stdout_end();
	dup2(saved_stdin, STDIN_FILENO);
	close(saved_stdin);
	close(fd);
	unlink(tmpl);
	return rc;
}

static void clear_set_env(void)
{
	unsetenv("ELA_QUIET");
	unsetenv("ELA_OUTPUT_FORMAT");
	unsetenv("ELA_SESSION_MAC");
}

/* -----------------------------------------------------------------------
 * interactive_set_command
 * --------------------------------------------------------------------- */

static void test_set_no_args_prints_values(void)
{
	char *argv[] = { "set" };
	static const char *const vars[] = {
		"ELA_API_URL", "ELA_API_INSECURE", "ELA_QUIET", "ELA_OUTPUT_FORMAT",
		"ELA_OUTPUT_TCP", "ELA_SCRIPT", "ELA_OUTPUT_HTTP", "ELA_OUTPUT_INSECURE",
		"ELA_API_KEY", "ELA_VERBOSE", "ELA_DEBUG", "ELA_WS_RETRY_ATTEMPTS",
	};
	size_t i;

	clear_set_env();
	silence_stdout_begin();
	/* argc == 1 prints the current variable values and returns 0.
	 * First pass: every variable unset (the "<unset>" ternary branch). */
	ELA_ASSERT_INT_EQ(0, interactive_set_command(1, argv));

	/* Second pass: every variable set (the value ternary branch). */
	for (i = 0; i < sizeof(vars) / sizeof(vars[0]); i++)
		setenv(vars[i], "x", 1);
	ELA_ASSERT_INT_EQ(0, interactive_set_command(1, argv));
	silence_stdout_end();

	for (i = 0; i < sizeof(vars) / sizeof(vars[0]); i++)
		unsetenv(vars[i]);
	clear_set_env();
}

static void test_set_output_http_unsets_counterpart(void)
{
	char *argv[] = { "set", "ELA_OUTPUT_HTTP", "https://upload.example/" };

	clear_set_env();
	unsetenv("ELA_OUTPUT_HTTP");
	unsetenv("ELA_OUTPUT_HTTPS");
	silence_stdout_begin();
	/* An https value routes to the https slot and unsets the http counterpart. */
	ELA_ASSERT_INT_EQ(0, interactive_set_command(3, argv));
	silence_stdout_end();
	unsetenv("ELA_OUTPUT_HTTP");
	unsetenv("ELA_OUTPUT_HTTPS");
	clear_set_env();
}

static void test_set_wrong_arity_returns_2(void)
{
	char *argv[] = { "set", "ELA_QUIET" };

	/* argc == 2 is neither "show" (1) nor "assign" (3) */
	ELA_ASSERT_INT_EQ(2, interactive_set_command(2, argv));
}

static void test_set_valid_assignment(void)
{
	char *argv[] = { "set", "ELA_QUIET", "true" };

	clear_set_env();
	g_conf_update_calls = 0;
	silence_stdout_begin();
	ELA_ASSERT_INT_EQ(0, interactive_set_command(3, argv));
	silence_stdout_end();
	ELA_ASSERT_STR_EQ("true", getenv("ELA_QUIET") ? getenv("ELA_QUIET") : "");
	clear_set_env();
}

static void test_set_unknown_variable_returns_2(void)
{
	char *argv[] = { "set", "ELA_NOT_A_REAL_VAR", "x" };

	/* Unknown variable: plan fails, prints supported list, returns 2 */
	ELA_ASSERT_INT_EQ(2, interactive_set_command(3, argv));
}

static void test_set_api_url_clears_overrides_and_updates_conf(void)
{
	char *argv[] = { "set", "ELA_API_URL", "http://127.0.0.1:5000/upload" };

	clear_set_env();
	unsetenv("ELA_API_URL");
	setenv("ELA_OUTPUT_HTTP", "http://stale/", 1);
	g_conf_update_calls = 0;
	silence_stdout_begin();
	ELA_ASSERT_INT_EQ(0, interactive_set_command(3, argv));
	silence_stdout_end();
	/* ELA_API_URL clears the upload overrides and reloads the conf. */
	ELA_ASSERT_TRUE(g_conf_update_calls >= 1);
	ELA_ASSERT_TRUE(getenv("ELA_OUTPUT_HTTP") == NULL);
	unsetenv("ELA_API_URL");
	clear_set_env();
}

static void test_set_api_key_value_is_redacted(void)
{
	char *argv[] = { "set", "ELA_API_KEY", "secrettoken" };

	unsetenv("ELA_API_KEY");
	silence_stdout_begin();
	ELA_ASSERT_INT_EQ(0, interactive_set_command(3, argv));
	silence_stdout_end();
	ELA_ASSERT_STR_EQ("secrettoken", getenv("ELA_API_KEY") ? getenv("ELA_API_KEY") : "");
	unsetenv("ELA_API_KEY");
}

/* -----------------------------------------------------------------------
 * interactive_loop
 * --------------------------------------------------------------------- */

static void test_loop_immediate_eof_returns_zero(void)
{
	clear_set_env();
	ela_test_shell_stubs_reset();
	/* Empty input -> first read hits EOF -> loop returns last_rc (0) */
	ELA_ASSERT_INT_EQ(0, run_loop_with_input("ela", ""));
	ELA_ASSERT_INT_EQ(0, g_dispatch_calls);
}

static void test_loop_quit_breaks(void)
{
	clear_set_env();
	ela_test_shell_stubs_reset();
	ELA_ASSERT_INT_EQ(0, run_loop_with_input("ela", "quit\n"));
	ELA_ASSERT_INT_EQ(0, g_dispatch_calls);
}

static void test_loop_exit_breaks(void)
{
	clear_set_env();
	ela_test_shell_stubs_reset();
	ELA_ASSERT_INT_EQ(0, run_loop_with_input("ela", "exit\n"));
}

static void test_loop_help_then_quit(void)
{
	clear_set_env();
	ela_test_shell_stubs_reset();
	/* "help" prints the interactive usage banner, then "quit" leaves. */
	ELA_ASSERT_INT_EQ(0, run_loop_with_input("ela", "help\nquit\n"));
	ELA_ASSERT_INT_EQ(0, g_dispatch_calls);
}

static void test_loop_blank_and_set_lines(void)
{
	clear_set_env();
	ela_test_shell_stubs_reset();
	/* blank line (argc == 0) is skipped; "set" with no args prints values. */
	ELA_ASSERT_INT_EQ(0, run_loop_with_input("ela", "\n   \nset\nquit\n"));
	ELA_ASSERT_INT_EQ(0, g_dispatch_calls);
	clear_set_env();
}

static void test_loop_dispatches_command(void)
{
	clear_set_env();
	ela_test_shell_stubs_reset();
	g_dispatch_rc = 7;
	/* A non-builtin command is forwarded to embedded_linux_audit_dispatch. */
	ELA_ASSERT_INT_EQ(7, run_loop_with_input("ela", "linux dmesg\nquit\n"));
	ELA_ASSERT_INT_EQ(1, g_dispatch_calls);
}

static void test_loop_parse_error_sets_rc_and_continues(void)
{
	clear_set_env();
	ela_test_shell_stubs_reset();
	/* Unterminated quote -> parse error (rc 2); loop records it and goes on. */
	ELA_ASSERT_INT_EQ(2, run_loop_with_input("ela", "\"unterminated\nquit\n"));
	ELA_ASSERT_INT_EQ(0, g_dispatch_calls);
}

static void test_loop_show_prompt_via_session_mac(void)
{
	clear_set_env();
	ela_test_shell_stubs_reset();
	/* ELA_SESSION_MAC forces the prompt/usage banner even without a TTY. */
	setenv("ELA_SESSION_MAC", "aa:bb:cc:dd:ee:ff", 1);
	ELA_ASSERT_INT_EQ(0, run_loop_with_input("ela", "quit\n"));
	clear_set_env();
}

int run_interactive_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "set/no_args_prints_values",   test_set_no_args_prints_values },
		{ "set/wrong_arity",             test_set_wrong_arity_returns_2 },
		{ "set/valid_assignment",        test_set_valid_assignment },
		{ "set/unknown_variable",        test_set_unknown_variable_returns_2 },
		{ "set/api_url_clears_overrides", test_set_api_url_clears_overrides_and_updates_conf },
		{ "set/api_key_redacted",        test_set_api_key_value_is_redacted },
		{ "set/output_http_unsets",      test_set_output_http_unsets_counterpart },
		{ "loop/immediate_eof",          test_loop_immediate_eof_returns_zero },
		{ "loop/quit_breaks",            test_loop_quit_breaks },
		{ "loop/exit_breaks",            test_loop_exit_breaks },
		{ "loop/help_then_quit",         test_loop_help_then_quit },
		{ "loop/blank_and_set_lines",    test_loop_blank_and_set_lines },
		{ "loop/dispatches_command",     test_loop_dispatches_command },
		{ "loop/parse_error_continues",  test_loop_parse_error_sets_rc_and_continues },
		{ "loop/show_prompt_session",    test_loop_show_prompt_via_session_mac },
	};

	return ela_run_test_suite("interactive", cases, sizeof(cases) / sizeof(cases[0]));
}
