// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "test_shell_stubs.h"
#include "../../../agent/shell/script_exec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

static char g_script_path[256];

static int write_temp_script(const char *content)
{
	char tmpl[] = "/tmp/ela_script_XXXXXX";
	int fd = mkstemp(tmpl);

	if (fd < 0)
		return -1;
	if (write(fd, content, strlen(content)) < 0) {
		close(fd);
		unlink(tmpl);
		return -1;
	}
	close(fd);
	snprintf(g_script_path, sizeof(g_script_path), "%s", tmpl);
	return 0;
}

static void remove_temp_script(void)
{
	if (g_script_path[0]) {
		unlink(g_script_path);
		g_script_path[0] = '\0';
	}
}

static void clear_output_env(void)
{
	unsetenv("ELA_OUTPUT_HTTP");
	unsetenv("ELA_OUTPUT_HTTPS");
	unsetenv("ELA_OUTPUT_INSECURE");
	unsetenv("ELA_QUIET");
}

/* -----------------------------------------------------------------------
 * Argument / open-failure guards
 * --------------------------------------------------------------------- */

static void test_null_and_empty_args_return_2(void)
{
	clear_output_env();
	ELA_ASSERT_INT_EQ(2, execute_script_commands(NULL, "x"));
	ELA_ASSERT_INT_EQ(2, execute_script_commands("ela", NULL));
	ELA_ASSERT_INT_EQ(2, execute_script_commands("ela", ""));
}

static void test_missing_local_file_returns_2(void)
{
	clear_output_env();
	ela_test_shell_stubs_reset();
	/* No ELA_OUTPUT_HTTP set -> no fallback -> fopen() fails -> 2 */
	ELA_ASSERT_INT_EQ(2, execute_script_commands("ela", "/no/such/ela_script_zzz.txt"));
}

/* -----------------------------------------------------------------------
 * Local script execution
 * --------------------------------------------------------------------- */

static void test_local_script_mixed_lines(void)
{
	clear_output_env();
	ela_test_shell_stubs_reset();
	ELA_ASSERT_INT_EQ(0, write_temp_script(
		"# a comment\n"
		"   \n"
		"help\n"
		"set ELA_QUIET true\n"
		"linux dmesg\n"));

	ELA_ASSERT_INT_EQ(0, execute_script_commands("ela", g_script_path));
	ELA_ASSERT_INT_EQ(1, g_usage_calls);     /* "help" */
	ELA_ASSERT_INT_EQ(1, g_dispatch_calls);  /* "linux dmesg" */

	remove_temp_script();
	clear_output_env();
}

static void test_local_script_parse_error_returns_2(void)
{
	clear_output_env();
	ela_test_shell_stubs_reset();
	/* Unterminated quote triggers a parse failure mid-script. */
	ELA_ASSERT_INT_EQ(0, write_temp_script("\"unterminated\n"));
	ELA_ASSERT_INT_EQ(2, execute_script_commands("ela", g_script_path));
	ELA_ASSERT_INT_EQ(0, g_dispatch_calls);
	remove_temp_script();
}

static void test_local_script_only_comments_and_blanks(void)
{
	clear_output_env();
	ela_test_shell_stubs_reset();
	ELA_ASSERT_INT_EQ(0, write_temp_script("# only comments\n\n\t\n# done\n"));
	ELA_ASSERT_INT_EQ(0, execute_script_commands("ela", g_script_path));
	ELA_ASSERT_INT_EQ(0, g_dispatch_calls);
	ELA_ASSERT_INT_EQ(0, g_usage_calls);
	remove_temp_script();
}

static void test_local_script_invalid_command_returns_2(void)
{
	clear_output_env();
	ela_test_shell_stubs_reset();
	/* "ela" with no following command fails dispatch planning. */
	ELA_ASSERT_INT_EQ(0, write_temp_script("ela\n"));
	ELA_ASSERT_INT_EQ(2, execute_script_commands("ela", g_script_path));
	ELA_ASSERT_INT_EQ(0, g_dispatch_calls);
	remove_temp_script();
}

static void test_local_script_set_failure_returns_2(void)
{
	clear_output_env();
	ela_test_shell_stubs_reset();
	/* A bad "set" inside the script aborts execution with the set's rc. */
	ELA_ASSERT_INT_EQ(0, write_temp_script("set ELA_NOT_A_REAL_VAR value\n"));
	ELA_ASSERT_INT_EQ(2, execute_script_commands("ela", g_script_path));
	remove_temp_script();
	clear_output_env();
}

/* -----------------------------------------------------------------------
 * HTTP-sourced script
 * --------------------------------------------------------------------- */

static void test_http_source_success(void)
{
	clear_output_env();
	ela_test_shell_stubs_reset();
	g_http_get_rc = 0;                       /* fetch "succeeds" */
	g_http_get_payload = "# remote script\nhelp\nlinux dmesg\n";

	ELA_ASSERT_INT_EQ(0, execute_script_commands("ela", "http://example.com/script.txt"));
	ELA_ASSERT_INT_EQ(1, g_http_get_calls);
	ELA_ASSERT_INT_EQ(1, g_usage_calls);
	ELA_ASSERT_INT_EQ(1, g_dispatch_calls);
	clear_output_env();
}

static void test_http_source_fetch_failure_returns_2(void)
{
	clear_output_env();
	ela_test_shell_stubs_reset();
	g_http_get_rc = -1;                      /* fetch fails */

	ELA_ASSERT_INT_EQ(2, execute_script_commands("ela", "https://example.com/script.txt"));
	ELA_ASSERT_INT_EQ(1, g_http_get_calls);
	clear_output_env();
}

static void test_http_source_insecure_flag(void)
{
	clear_output_env();
	ela_test_shell_stubs_reset();
	/* Exercises the ELA_OUTPUT_INSECURE="1" branch at the top of the fn. */
	setenv("ELA_OUTPUT_INSECURE", "1", 1);
	g_http_get_rc = 0;
	g_http_get_payload = "# remote\nhelp\n";

	ELA_ASSERT_INT_EQ(0, execute_script_commands("ela", "http://example.com/script.txt"));
	ELA_ASSERT_INT_EQ(1, g_http_get_calls);
	clear_output_env();
}

/* -----------------------------------------------------------------------
 * Fallback URI (local file missing + ELA_OUTPUT_HTTP configured)
 * --------------------------------------------------------------------- */

static void test_fallback_uri_success(void)
{
	clear_output_env();
	ela_test_shell_stubs_reset();
	setenv("ELA_OUTPUT_HTTP", "http://server.example/", 1);
	g_http_get_rc = 0;
	g_http_get_payload = "linux dmesg\n";

	/* Local file does not exist, so the fallback HTTP fetch is attempted. */
	ELA_ASSERT_INT_EQ(0, execute_script_commands("ela", "ela_missing_script_abc123.txt"));
	ELA_ASSERT_INT_EQ(1, g_http_get_calls);
	ELA_ASSERT_INT_EQ(1, g_dispatch_calls);
	clear_output_env();
}

static void test_fallback_uri_fetch_failure_returns_2(void)
{
	clear_output_env();
	ela_test_shell_stubs_reset();
	setenv("ELA_OUTPUT_HTTPS", "https://server.example/", 1);
	g_http_get_rc = -1;

	ELA_ASSERT_INT_EQ(2, execute_script_commands("ela", "ela_missing_script_def456.txt"));
	ELA_ASSERT_INT_EQ(1, g_http_get_calls);
	clear_output_env();
}

int run_script_exec_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "args/null_and_empty",         test_null_and_empty_args_return_2 },
		{ "open/missing_local_file",     test_missing_local_file_returns_2 },
		{ "local/mixed_lines",           test_local_script_mixed_lines },
		{ "local/parse_error",           test_local_script_parse_error_returns_2 },
		{ "local/comments_and_blanks",   test_local_script_only_comments_and_blanks },
		{ "local/invalid_command",       test_local_script_invalid_command_returns_2 },
		{ "local/set_failure",           test_local_script_set_failure_returns_2 },
		{ "http/source_success",         test_http_source_success },
		{ "http/source_fetch_failure",   test_http_source_fetch_failure_returns_2 },
		{ "http/source_insecure_flag",   test_http_source_insecure_flag },
		{ "fallback/uri_success",        test_fallback_uri_success },
		{ "fallback/uri_fetch_failure",  test_fallback_uri_fetch_failure_returns_2 },
	};

	return ela_run_test_suite("script_exec", cases, sizeof(cases) / sizeof(cases[0]));
}
