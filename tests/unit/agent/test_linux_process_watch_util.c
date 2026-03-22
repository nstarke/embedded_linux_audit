// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/linux/linux_process_watch_util.h"

#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * ela_process_watch_needle_is_valid
 * ====================================================================== */

static void test_needle_null_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_process_watch_needle_is_valid(NULL));
}

static void test_needle_empty_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_process_watch_needle_is_valid(""));
}

static void test_needle_too_long_returns_false(void)
{
	char long_needle[ELA_PROCESS_WATCH_NEEDLE_MAX + 2];

	memset(long_needle, 'x', ELA_PROCESS_WATCH_NEEDLE_MAX + 1);
	long_needle[ELA_PROCESS_WATCH_NEEDLE_MAX + 1] = '\0';
	ELA_ASSERT_FALSE(ela_process_watch_needle_is_valid(long_needle));
}

static void test_needle_with_newline_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_process_watch_needle_is_valid("sshd\n"));
	ELA_ASSERT_FALSE(ela_process_watch_needle_is_valid("ss\rhd"));
}

static void test_needle_with_tab_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_process_watch_needle_is_valid("ss\thd"));
}

static void test_needle_valid_simple(void)
{
	ELA_ASSERT_TRUE(ela_process_watch_needle_is_valid("sshd"));
}

static void test_needle_valid_with_spaces_and_dashes(void)
{
	ELA_ASSERT_TRUE(ela_process_watch_needle_is_valid("my-service --config /etc/svc.conf"));
}

static void test_needle_exactly_max_length_is_valid(void)
{
	char needle[ELA_PROCESS_WATCH_NEEDLE_MAX + 1];

	memset(needle, 'a', ELA_PROCESS_WATCH_NEEDLE_MAX);
	needle[ELA_PROCESS_WATCH_NEEDLE_MAX] = '\0';
	ELA_ASSERT_TRUE(ela_process_watch_needle_is_valid(needle));
}

/* =========================================================================
 * ela_process_watch_state_parse_line
 * ====================================================================== */

static void test_parse_null_line_returns_minus1(void)
{
	char n[64], p[64];

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_parse_line(NULL, n, sizeof(n), p, sizeof(p)));
}

static void test_parse_null_needle_out_returns_minus1(void)
{
	char p[64];

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_parse_line("sshd\t1234\n", NULL, 64, p, sizeof(p)));
}

static void test_parse_null_pids_out_returns_minus1(void)
{
	char n[64];

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_parse_line("sshd\t1234\n", n, sizeof(n), NULL, 64));
}

static void test_parse_no_tab_returns_minus1(void)
{
	char n[64], p[64];

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_parse_line("sshd1234\n", n, sizeof(n), p, sizeof(p)));
}

static void test_parse_small_needle_buf_returns_minus1(void)
{
	char n[2], p[64]; /* "sshd" won't fit in 2 bytes */

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_parse_line("sshd\t1234\n", n, sizeof(n), p, sizeof(p)));
}

static void test_parse_small_pids_buf_returns_minus1(void)
{
	char n[64], p[3]; /* "1234" won't fit in 3 bytes */

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_parse_line("sshd\t1234\n", n, sizeof(n), p, sizeof(p)));
}

static void test_parse_empty_needle_returns_minus1(void)
{
	char n[64], p[64];

	/* Tab at position 0 means zero-length needle — invalid */
	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_parse_line("\t1234\n", n, sizeof(n), p, sizeof(p)));
}

static void test_parse_valid_line_with_single_pid(void)
{
	char n[64], p[64];

	ELA_ASSERT_INT_EQ(0, ela_process_watch_state_parse_line("sshd\t1234\n", n, sizeof(n), p, sizeof(p)));
	ELA_ASSERT_STR_EQ("sshd", n);
	ELA_ASSERT_STR_EQ("1234", p);
}

static void test_parse_valid_line_with_multiple_pids(void)
{
	char n[64], p[64];

	ELA_ASSERT_INT_EQ(0, ela_process_watch_state_parse_line("nginx\t1234,5678,9012\n",
								n, sizeof(n), p, sizeof(p)));
	ELA_ASSERT_STR_EQ("nginx", n);
	ELA_ASSERT_STR_EQ("1234,5678,9012", p);
}

static void test_parse_valid_line_empty_pids(void)
{
	char n[64], p[64];

	/* Empty PID list is valid (process not currently running) */
	ELA_ASSERT_INT_EQ(0, ela_process_watch_state_parse_line("sshd\t\n",
								n, sizeof(n), p, sizeof(p)));
	ELA_ASSERT_STR_EQ("sshd", n);
	ELA_ASSERT_STR_EQ("", p);
}

static void test_parse_no_trailing_newline(void)
{
	char n[64], p[64];

	ELA_ASSERT_INT_EQ(0, ela_process_watch_state_parse_line("sshd\t1234",
								n, sizeof(n), p, sizeof(p)));
	ELA_ASSERT_STR_EQ("sshd", n);
	ELA_ASSERT_STR_EQ("1234", p);
}

/* =========================================================================
 * ela_process_watch_state_format_line
 * ====================================================================== */

static void test_format_null_needle_returns_minus1(void)
{
	char out[64];

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_format_line(NULL, "1234", out, sizeof(out)));
}

static void test_format_null_pids_returns_minus1(void)
{
	char out[64];

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_format_line("sshd", NULL, out, sizeof(out)));
}

static void test_format_null_out_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_format_line("sshd", "1234", NULL, 64));
}

static void test_format_small_buf_returns_minus1(void)
{
	char out[4]; /* "sshd\t1234\n" needs more than 4 bytes */

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_format_line("sshd", "1234", out, sizeof(out)));
}

static void test_format_empty_needle_returns_minus1(void)
{
	char out[64];

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_state_format_line("", "1234", out, sizeof(out)));
}

static void test_format_valid_produces_tab_separated_line(void)
{
	char out[128];

	ELA_ASSERT_INT_EQ(0, ela_process_watch_state_format_line("sshd", "1234", out, sizeof(out)));
	ELA_ASSERT_STR_EQ("sshd\t1234\n", out);
}

static void test_format_empty_pids_allowed(void)
{
	char out[128];

	ELA_ASSERT_INT_EQ(0, ela_process_watch_state_format_line("sshd", "", out, sizeof(out)));
	ELA_ASSERT_STR_EQ("sshd\t\n", out);
}

/* =========================================================================
 * ela_process_watch_pids_equal
 * ====================================================================== */

static void test_pids_equal_both_null(void)
{
	ELA_ASSERT_TRUE(ela_process_watch_pids_equal(NULL, NULL));
}

static void test_pids_equal_both_empty(void)
{
	ELA_ASSERT_TRUE(ela_process_watch_pids_equal("", ""));
}

static void test_pids_equal_null_and_empty(void)
{
	/* NULL is normalized to "" */
	ELA_ASSERT_TRUE(ela_process_watch_pids_equal(NULL, ""));
	ELA_ASSERT_TRUE(ela_process_watch_pids_equal("", NULL));
}

static void test_pids_equal_identical_single(void)
{
	ELA_ASSERT_TRUE(ela_process_watch_pids_equal("1234", "1234"));
}

static void test_pids_equal_identical_multiple(void)
{
	ELA_ASSERT_TRUE(ela_process_watch_pids_equal("1234,5678", "1234,5678"));
}

static void test_pids_not_equal_different_single(void)
{
	ELA_ASSERT_FALSE(ela_process_watch_pids_equal("1234", "5678"));
}

static void test_pids_not_equal_one_empty(void)
{
	ELA_ASSERT_FALSE(ela_process_watch_pids_equal("", "1234"));
	ELA_ASSERT_FALSE(ela_process_watch_pids_equal("1234", ""));
}

static void test_pids_not_equal_different_sets(void)
{
	ELA_ASSERT_FALSE(ela_process_watch_pids_equal("1234,5678", "1234,9999"));
}

/* =========================================================================
 * ela_process_watch_format_event
 * ====================================================================== */

static void test_event_null_needle_returns_minus1(void)
{
	char *out = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_format_event(NULL, "1234", "5678", "txt", &out, &len));
}

static void test_event_null_old_pids_returns_minus1(void)
{
	char *out = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_format_event("sshd", NULL, "5678", "txt", &out, &len));
}

static void test_event_null_new_pids_returns_minus1(void)
{
	char *out = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_format_event("sshd", "1234", NULL, "txt", &out, &len));
}

static void test_event_txt_format(void)
{
	char *out = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(0, ela_process_watch_format_event("sshd", "1234", "5678",
							     "txt", &out, &len));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(len > 0);
	ELA_ASSERT_TRUE(strstr(out, "process_watch") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "sshd") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "1234") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "5678") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "old_pids") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "new_pids") != NULL);
	free(out);
}

static void test_event_csv_format(void)
{
	char *out = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(0, ela_process_watch_format_event("sshd", "1234", "5678",
							     "csv", &out, &len));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "process_watch") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "sshd") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "1234") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "5678") != NULL);
	/* CSV rows must end with a newline */
	ELA_ASSERT_INT_EQ('\n', out[len - 1]);
	free(out);
}

static void test_event_json_format(void)
{
	char *out = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(0, ela_process_watch_format_event("sshd", "1234", "5678",
							     "json", &out, &len));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"process_watch\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"sshd\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"old_pids\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"new_pids\"") != NULL);
	ELA_ASSERT_INT_EQ('\n', out[len - 1]);
	free(out);
}

/* =========================================================================
 * ela_process_watch_format_list_entry
 * ====================================================================== */

static void test_list_null_needle_returns_minus1(void)
{
	char *out = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_format_list_entry(NULL, "1234", "txt", &out, &len));
}

static void test_list_null_pids_returns_minus1(void)
{
	char *out = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(-1, ela_process_watch_format_list_entry("sshd", NULL, "txt", &out, &len));
}

static void test_list_txt_format(void)
{
	char *out = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(0, ela_process_watch_format_list_entry("sshd", "1234,5678",
								  "txt", &out, &len));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "process_watch_list") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "sshd") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "1234,5678") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "pids") != NULL);
	free(out);
}

static void test_list_csv_format(void)
{
	char *out = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(0, ela_process_watch_format_list_entry("nginx", "9000",
								  "csv", &out, &len));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "process_watch_list") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "nginx") != NULL);
	ELA_ASSERT_INT_EQ('\n', out[len - 1]);
	free(out);
}

static void test_list_json_format(void)
{
	char *out = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(0, ela_process_watch_format_list_entry("nginx", "9000",
								  "json", &out, &len));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"process_watch_list\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"nginx\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"pids\"") != NULL);
	ELA_ASSERT_INT_EQ('\n', out[len - 1]);
	free(out);
}

static void test_list_empty_pids_ok(void)
{
	char *out = NULL;
	size_t len = 0;

	/* Process not currently running — empty pids must not crash */
	ELA_ASSERT_INT_EQ(0, ela_process_watch_format_list_entry("sshd", "",
								  "txt", &out, &len));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "sshd") != NULL);
	free(out);
}

/* =========================================================================
 * ela_process_watch_content_type
 * ====================================================================== */

static void test_content_type_json(void)
{
	ELA_ASSERT_STR_EQ("application/json; charset=utf-8",
			  ela_process_watch_content_type("json"));
}

static void test_content_type_csv(void)
{
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8",
			  ela_process_watch_content_type("csv"));
}

static void test_content_type_txt(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_process_watch_content_type("txt"));
}

static void test_content_type_unknown(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_process_watch_content_type("xml"));
}

static void test_content_type_null(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_process_watch_content_type(NULL));
}

/* =========================================================================
 * Round-trip: format_line then state_parse_line
 * ====================================================================== */

static void test_roundtrip_format_then_parse(void)
{
	char line[256];
	char needle_out[64], pids_out[64];

	ELA_ASSERT_INT_EQ(0, ela_process_watch_state_format_line(
		"nginx", "100,200,300", line, sizeof(line)));
	ELA_ASSERT_INT_EQ(0, ela_process_watch_state_parse_line(
		line, needle_out, sizeof(needle_out),
		pids_out, sizeof(pids_out)));
	ELA_ASSERT_STR_EQ("nginx",       needle_out);
	ELA_ASSERT_STR_EQ("100,200,300", pids_out);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_linux_process_watch_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* ela_process_watch_needle_is_valid */
		{ "needle/null",               test_needle_null_returns_false },
		{ "needle/empty",              test_needle_empty_returns_false },
		{ "needle/too_long",           test_needle_too_long_returns_false },
		{ "needle/newline",            test_needle_with_newline_returns_false },
		{ "needle/tab",                test_needle_with_tab_returns_false },
		{ "needle/valid_simple",       test_needle_valid_simple },
		{ "needle/valid_complex",      test_needle_valid_with_spaces_and_dashes },
		{ "needle/valid_max_length",   test_needle_exactly_max_length_is_valid },
		/* ela_process_watch_state_parse_line */
		{ "parse/null_line",           test_parse_null_line_returns_minus1 },
		{ "parse/null_needle_out",     test_parse_null_needle_out_returns_minus1 },
		{ "parse/null_pids_out",       test_parse_null_pids_out_returns_minus1 },
		{ "parse/no_tab",              test_parse_no_tab_returns_minus1 },
		{ "parse/small_needle_buf",    test_parse_small_needle_buf_returns_minus1 },
		{ "parse/small_pids_buf",      test_parse_small_pids_buf_returns_minus1 },
		{ "parse/empty_needle",        test_parse_empty_needle_returns_minus1 },
		{ "parse/single_pid",          test_parse_valid_line_with_single_pid },
		{ "parse/multiple_pids",       test_parse_valid_line_with_multiple_pids },
		{ "parse/empty_pids",          test_parse_valid_line_empty_pids },
		{ "parse/no_trailing_newline", test_parse_no_trailing_newline },
		/* ela_process_watch_state_format_line */
		{ "format_line/null_needle",   test_format_null_needle_returns_minus1 },
		{ "format_line/null_pids",     test_format_null_pids_returns_minus1 },
		{ "format_line/null_out",      test_format_null_out_returns_minus1 },
		{ "format_line/small_buf",     test_format_small_buf_returns_minus1 },
		{ "format_line/empty_needle",  test_format_empty_needle_returns_minus1 },
		{ "format_line/valid",         test_format_valid_produces_tab_separated_line },
		{ "format_line/empty_pids",    test_format_empty_pids_allowed },
		/* ela_process_watch_pids_equal */
		{ "pids_equal/both_null",      test_pids_equal_both_null },
		{ "pids_equal/both_empty",     test_pids_equal_both_empty },
		{ "pids_equal/null_and_empty", test_pids_equal_null_and_empty },
		{ "pids_equal/same_single",    test_pids_equal_identical_single },
		{ "pids_equal/same_multiple",  test_pids_equal_identical_multiple },
		{ "pids_equal/diff_single",    test_pids_not_equal_different_single },
		{ "pids_equal/one_empty",      test_pids_not_equal_one_empty },
		{ "pids_equal/diff_sets",      test_pids_not_equal_different_sets },
		/* ela_process_watch_format_event */
		{ "event/null_needle",         test_event_null_needle_returns_minus1 },
		{ "event/null_old_pids",       test_event_null_old_pids_returns_minus1 },
		{ "event/null_new_pids",       test_event_null_new_pids_returns_minus1 },
		{ "event/txt",                 test_event_txt_format },
		{ "event/csv",                 test_event_csv_format },
		{ "event/json",                test_event_json_format },
		/* ela_process_watch_format_list_entry */
		{ "list/null_needle",          test_list_null_needle_returns_minus1 },
		{ "list/null_pids",            test_list_null_pids_returns_minus1 },
		{ "list/txt",                  test_list_txt_format },
		{ "list/csv",                  test_list_csv_format },
		{ "list/json",                 test_list_json_format },
		{ "list/empty_pids",           test_list_empty_pids_ok },
		/* ela_process_watch_content_type */
		{ "content_type/json",         test_content_type_json },
		{ "content_type/csv",          test_content_type_csv },
		{ "content_type/txt",          test_content_type_txt },
		{ "content_type/unknown",      test_content_type_unknown },
		{ "content_type/null",         test_content_type_null },
		/* roundtrip */
		{ "roundtrip/format_parse",    test_roundtrip_format_then_parse },
	};

	return ela_run_test_suite("linux_process_watch_util",
				  cases, sizeof(cases) / sizeof(cases[0]));
}
