// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/shell/script_exec_util.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * ela_script_is_http_source
 * ---------------------------------------------------------------------- */

static void test_is_http_source_null(void)
{
	ELA_ASSERT_FALSE(ela_script_is_http_source(NULL));
}

static void test_is_http_source_empty(void)
{
	ELA_ASSERT_FALSE(ela_script_is_http_source(""));
}

static void test_is_http_source_http(void)
{
	ELA_ASSERT_TRUE(ela_script_is_http_source("http://ela.example/script.ela"));
	ELA_ASSERT_TRUE(ela_script_is_http_source("http://"));
}

static void test_is_http_source_https(void)
{
	ELA_ASSERT_TRUE(ela_script_is_http_source("https://ela.example/script.ela"));
	ELA_ASSERT_TRUE(ela_script_is_http_source("https://"));
}

static void test_is_http_source_local(void)
{
	ELA_ASSERT_FALSE(ela_script_is_http_source("/tmp/script.ela"));
	ELA_ASSERT_FALSE(ela_script_is_http_source("./script.ela"));
	ELA_ASSERT_FALSE(ela_script_is_http_source("script.ela"));
	ELA_ASSERT_FALSE(ela_script_is_http_source("ftp://host/path"));
}

/* -------------------------------------------------------------------------
 * ela_script_basename
 * ---------------------------------------------------------------------- */

static void test_basename_null(void)
{
	ELA_ASSERT_TRUE(ela_script_basename(NULL) == NULL);
}

static void test_basename_empty(void)
{
	ELA_ASSERT_TRUE(ela_script_basename("") == NULL);
}

static void test_basename_with_slash(void)
{
	ELA_ASSERT_STR_EQ("script.ela", ela_script_basename("/tmp/script.ela"));
	ELA_ASSERT_STR_EQ("script.ela", ela_script_basename("/a/b/c/script.ela"));
}

static void test_basename_no_slash(void)
{
	ELA_ASSERT_STR_EQ("script.ela", ela_script_basename("script.ela"));
}

static void test_basename_url(void)
{
	ELA_ASSERT_STR_EQ("script.ela", ela_script_basename("https://ela.example/scripts/script.ela"));
}

static void test_basename_trailing_slash(void)
{
	/* strrchr finds last '/', returns empty string after it */
	ELA_ASSERT_STR_EQ("", ela_script_basename("/tmp/dir/"));
}

/* -------------------------------------------------------------------------
 * ela_script_url_percent_encode
 * ---------------------------------------------------------------------- */

static void test_percent_encode_null(void)
{
	ELA_ASSERT_TRUE(ela_script_url_percent_encode(NULL) == NULL);
}

static void test_percent_encode_empty(void)
{
	char *out = ela_script_url_percent_encode("");

	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_STR_EQ("", out);
	free(out);
}

static void test_percent_encode_alphanumeric(void)
{
	char *out = ela_script_url_percent_encode("abc123");

	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_STR_EQ("abc123", out);
	free(out);
}

static void test_percent_encode_unreserved_chars(void)
{
	/* RFC 3986 unreserved: - _ . ~ */
	char *out = ela_script_url_percent_encode("a-b_c.d~e");

	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_STR_EQ("a-b_c.d~e", out);
	free(out);
}

static void test_percent_encode_space(void)
{
	char *out = ela_script_url_percent_encode("fw script.ela");

	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_STR_EQ("fw%20script.ela", out);
	free(out);
}

static void test_percent_encode_slash(void)
{
	char *out = ela_script_url_percent_encode("a/b");

	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_STR_EQ("a%2Fb", out);
	free(out);
}

static void test_percent_encode_special_chars(void)
{
	char *out = ela_script_url_percent_encode("#?&=");

	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_STR_EQ("%23%3F%26%3D", out);
	free(out);
}

static void test_percent_encode_mixed(void)
{
	/* "fw script v1.0.ela" — space and dots/alphanumeric */
	char *out = ela_script_url_percent_encode("fw script v1.0.ela");

	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "%20") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "v1.0.ela") != NULL);
	free(out);
}

/* -------------------------------------------------------------------------
 * ela_script_build_fallback_uri
 * ---------------------------------------------------------------------- */

static void test_fallback_uri_null_output_uri(void)
{
	ELA_ASSERT_TRUE(ela_script_build_fallback_uri(NULL, "/tmp/s.ela") == NULL);
}

static void test_fallback_uri_empty_output_uri(void)
{
	ELA_ASSERT_TRUE(ela_script_build_fallback_uri("", "/tmp/s.ela") == NULL);
}

static void test_fallback_uri_null_script_source(void)
{
	ELA_ASSERT_TRUE(ela_script_build_fallback_uri("https://ela.example/api", NULL) == NULL);
}

static void test_fallback_uri_empty_script_source(void)
{
	ELA_ASSERT_TRUE(ela_script_build_fallback_uri("https://ela.example/api", "") == NULL);
}

static void test_fallback_uri_no_scheme(void)
{
	/* output_uri without "://" */
	ELA_ASSERT_TRUE(ela_script_build_fallback_uri("ela.example/api", "/tmp/s.ela") == NULL);
}

static void test_fallback_uri_normal_https(void)
{
	char *uri = ela_script_build_fallback_uri("https://ela.example/api/data",
						   "/tmp/fw script.ela");

	ELA_ASSERT_TRUE(uri != NULL);
	ELA_ASSERT_STR_EQ("https://ela.example/scripts/fw%20script.ela", uri);
	free(uri);
}

static void test_fallback_uri_normal_http(void)
{
	char *uri = ela_script_build_fallback_uri("http://host:8080/any/path",
						   "/path/to/script.ela");

	ELA_ASSERT_TRUE(uri != NULL);
	ELA_ASSERT_STR_EQ("http://host:8080/scripts/script.ela", uri);
	free(uri);
}

static void test_fallback_uri_output_uri_no_path(void)
{
	/* output_uri with only authority, no path */
	char *uri = ela_script_build_fallback_uri("https://host:9000", "/tmp/s.ela");

	ELA_ASSERT_TRUE(uri != NULL);
	ELA_ASSERT_STR_EQ("https://host:9000/scripts/s.ela", uri);
	free(uri);
}

/* -------------------------------------------------------------------------
 * ela_script_trim
 * ---------------------------------------------------------------------- */

static void test_trim_null(void)
{
	ELA_ASSERT_TRUE(ela_script_trim(NULL) == NULL);
}

static void test_trim_empty(void)
{
	char s[] = "";

	ELA_ASSERT_STR_EQ("", ela_script_trim(s));
}

static void test_trim_no_whitespace(void)
{
	char s[] = "linux dmesg";

	ELA_ASSERT_STR_EQ("linux dmesg", ela_script_trim(s));
}

static void test_trim_leading_and_trailing(void)
{
	char s[] = " \t linux dmesg \n";

	ELA_ASSERT_STR_EQ("linux dmesg", ela_script_trim(s));
}

static void test_trim_only_whitespace(void)
{
	char s[] = "   \t\n  ";

	ELA_ASSERT_STR_EQ("", ela_script_trim(s));
}

static void test_trim_leading_only(void)
{
	char s[] = "   linux";

	ELA_ASSERT_STR_EQ("linux", ela_script_trim(s));
}

static void test_trim_trailing_only(void)
{
	char s[] = "linux   ";

	ELA_ASSERT_STR_EQ("linux", ela_script_trim(s));
}

/* -------------------------------------------------------------------------
 * ela_script_line_is_ignorable
 * ---------------------------------------------------------------------- */

static void test_ignorable_null(void)
{
	ELA_ASSERT_TRUE(ela_script_line_is_ignorable(NULL));
}

static void test_ignorable_empty(void)
{
	ELA_ASSERT_TRUE(ela_script_line_is_ignorable(""));
}

static void test_ignorable_comment(void)
{
	ELA_ASSERT_TRUE(ela_script_line_is_ignorable("# comment"));
	ELA_ASSERT_TRUE(ela_script_line_is_ignorable("#no space"));
	ELA_ASSERT_TRUE(ela_script_line_is_ignorable("#"));
}

static void test_ignorable_not_ignorable(void)
{
	ELA_ASSERT_FALSE(ela_script_line_is_ignorable("linux dmesg"));
	ELA_ASSERT_FALSE(ela_script_line_is_ignorable("help"));
	ELA_ASSERT_FALSE(ela_script_line_is_ignorable("set ELA_DEBUG true"));
	/* a space before '#' means it's not a comment — it's a token */
	ELA_ASSERT_FALSE(ela_script_line_is_ignorable(" #not a comment"));
}

/* -------------------------------------------------------------------------
 * ela_script_plan_dispatch
 * ---------------------------------------------------------------------- */

static void test_plan_dispatch_null_plan(void)
{
	char *argv[] = { "linux", "dmesg" };
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_script_plan_dispatch(2, argv, NULL, errbuf, sizeof(errbuf)));
}

static void test_plan_dispatch_argc_zero(void)
{
	struct ela_script_dispatch_plan plan;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_script_plan_dispatch(0, NULL, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "empty") != NULL);
}

static void test_plan_dispatch_argc_negative(void)
{
	struct ela_script_dispatch_plan plan;
	char errbuf[128] = { 0 };
	char *argv[] = { "linux" };

	ELA_ASSERT_INT_EQ(-1, ela_script_plan_dispatch(-1, argv, &plan, errbuf, sizeof(errbuf)));
}

static void test_plan_dispatch_argc_positive_null_argv(void)
{
	struct ela_script_dispatch_plan plan;

	ELA_ASSERT_INT_EQ(-1, ela_script_plan_dispatch(1, NULL, &plan, NULL, 0));
}

static void test_plan_dispatch_help(void)
{
	struct ela_script_dispatch_plan plan;
	char *argv[] = { "help" };

	ELA_ASSERT_INT_EQ(0, ela_script_plan_dispatch(1, argv, &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_SCRIPT_COMMAND_HELP, plan.kind);
}

static void test_plan_dispatch_set(void)
{
	struct ela_script_dispatch_plan plan;
	char *argv[] = { "set", "ELA_DEBUG", "true" };

	ELA_ASSERT_INT_EQ(0, ela_script_plan_dispatch(3, argv, &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_SCRIPT_COMMAND_SET, plan.kind);
}

static void test_plan_dispatch_plain_command(void)
{
	struct ela_script_dispatch_plan plan;
	char *argv[] = { "linux", "dmesg" };

	ELA_ASSERT_INT_EQ(0, ela_script_plan_dispatch(2, argv, &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_SCRIPT_COMMAND_DISPATCH, plan.kind);
	ELA_ASSERT_INT_EQ(0, plan.script_cmd_idx);
	ELA_ASSERT_INT_EQ(3, plan.dispatch_argc); /* argc + 1 - 0 */
}

static void test_plan_dispatch_ela_prefix(void)
{
	struct ela_script_dispatch_plan plan;
	char *argv[] = { "ela", "linux", "dmesg" };

	ELA_ASSERT_INT_EQ(0, ela_script_plan_dispatch(3, argv, &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_SCRIPT_COMMAND_DISPATCH, plan.kind);
	ELA_ASSERT_INT_EQ(1, plan.script_cmd_idx);
	ELA_ASSERT_INT_EQ(3, plan.dispatch_argc); /* 3 + 1 - 1 */
}

static void test_plan_dispatch_embedded_linux_audit_prefix(void)
{
	struct ela_script_dispatch_plan plan;
	char *argv[] = { "embedded_linux_audit", "linux", "dmesg" };

	ELA_ASSERT_INT_EQ(0, ela_script_plan_dispatch(3, argv, &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_SCRIPT_COMMAND_DISPATCH, plan.kind);
	ELA_ASSERT_INT_EQ(1, plan.script_cmd_idx);
}

static void test_plan_dispatch_ela_alone_invalid(void)
{
	struct ela_script_dispatch_plan plan;
	char errbuf[128] = { 0 };
	char *argv[] = { "ela" };

	ELA_ASSERT_INT_EQ(-1, ela_script_plan_dispatch(1, argv, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "missing command") != NULL);
}

static void test_plan_dispatch_embedded_alone_invalid(void)
{
	struct ela_script_dispatch_plan plan;
	char errbuf[128] = { 0 };
	char *argv[] = { "embedded_linux_audit" };

	ELA_ASSERT_INT_EQ(-1, ela_script_plan_dispatch(1, argv, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "missing command") != NULL);
}

static void test_plan_dispatch_null_errbuf_ok(void)
{
	struct ela_script_dispatch_plan plan;
	char *argv[] = { "ela" };

	/* Must not crash with NULL errbuf */
	ELA_ASSERT_INT_EQ(-1, ela_script_plan_dispatch(1, argv, &plan, NULL, 0));
}

/* -------------------------------------------------------------------------
 * ela_script_local_file_exists
 * ---------------------------------------------------------------------- */

static void test_local_file_exists_null(void)
{
	ELA_ASSERT_FALSE(ela_script_local_file_exists(NULL));
}

static void test_local_file_exists_empty(void)
{
	ELA_ASSERT_FALSE(ela_script_local_file_exists(""));
}

static void test_local_file_exists_nonexistent(void)
{
	ELA_ASSERT_FALSE(ela_script_local_file_exists("/tmp/ela_test_no_such_file_xyz987.txt"));
}

static void test_local_file_exists_directory(void)
{
	ELA_ASSERT_FALSE(ela_script_local_file_exists("/tmp"));
}

static void test_local_file_exists_real_file(void)
{
	const char *path = "/tmp/ela_test_local_file_exists.tmp";
	FILE *f = fopen(path, "w");

	if (!f) {
		/* If we can't create the file, skip this check */
		return;
	}
	fclose(f);

	ELA_ASSERT_TRUE(ela_script_local_file_exists(path));

	unlink(path);
}

/* -------------------------------------------------------------------------
 * ela_script_create_temp_path
 * ---------------------------------------------------------------------- */

static void test_create_temp_path_null_dir(void)
{
	char file_path[256];

	ELA_ASSERT_INT_EQ(-1, ela_script_create_temp_path(NULL, 256,
							   file_path, sizeof(file_path),
							   "/tmp/s.ela"));
}

static void test_create_temp_path_zero_dir_len(void)
{
	char dir_path[256];
	char file_path[256];

	ELA_ASSERT_INT_EQ(-1, ela_script_create_temp_path(dir_path, 0,
							   file_path, sizeof(file_path),
							   "/tmp/s.ela"));
}

static void test_create_temp_path_null_file(void)
{
	char dir_path[256];

	ELA_ASSERT_INT_EQ(-1, ela_script_create_temp_path(dir_path, sizeof(dir_path),
							   NULL, 256,
							   "/tmp/s.ela"));
}

static void test_create_temp_path_zero_file_len(void)
{
	char dir_path[256];
	char file_path[256];

	ELA_ASSERT_INT_EQ(-1, ela_script_create_temp_path(dir_path, sizeof(dir_path),
							   file_path, 0,
							   "/tmp/s.ela"));
}

static void test_create_temp_path_normal(void)
{
	char dir_path[256];
	char file_path[512];

	ELA_ASSERT_INT_EQ(0, ela_script_create_temp_path(dir_path, sizeof(dir_path),
							  file_path, sizeof(file_path),
							  "/tmp/script.ela"));
	ELA_ASSERT_TRUE(dir_path[0] != '\0');
	/* file_path should start with dir_path */
	ELA_ASSERT_INT_EQ(0, strncmp(file_path, dir_path, strlen(dir_path)));
	/* file_path should end with the script basename */
	ELA_ASSERT_TRUE(strstr(file_path, "script.ela") != NULL);

	/* Cleanup: only the directory was created, not the file */
	rmdir(dir_path);
}

static void test_create_temp_path_null_source_uses_default(void)
{
	char dir_path[256];
	char file_path[512];

	ELA_ASSERT_INT_EQ(0, ela_script_create_temp_path(dir_path, sizeof(dir_path),
							  file_path, sizeof(file_path),
							  NULL));
	ELA_ASSERT_TRUE(strstr(file_path, "script.txt") != NULL);
	rmdir(dir_path);
}

static void test_create_temp_path_file_buf_too_small(void)
{
	char dir_path[256];
	char file_path[4]; /* too small for the full path */

	ELA_ASSERT_INT_EQ(-1, ela_script_create_temp_path(dir_path, sizeof(dir_path),
							   file_path, sizeof(file_path),
							   "/tmp/script.ela"));
	/* dir_path should have been zeroed on failure */
	ELA_ASSERT_INT_EQ('\0', dir_path[0]);
}

int run_script_exec_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* is_http_source */
		{ "is_http_source_null",                test_is_http_source_null },
		{ "is_http_source_empty",               test_is_http_source_empty },
		{ "is_http_source_http",                test_is_http_source_http },
		{ "is_http_source_https",               test_is_http_source_https },
		{ "is_http_source_local",               test_is_http_source_local },
		/* basename */
		{ "basename_null",                      test_basename_null },
		{ "basename_empty",                     test_basename_empty },
		{ "basename_with_slash",                test_basename_with_slash },
		{ "basename_no_slash",                  test_basename_no_slash },
		{ "basename_url",                       test_basename_url },
		{ "basename_trailing_slash",            test_basename_trailing_slash },
		/* percent_encode */
		{ "percent_encode_null",                test_percent_encode_null },
		{ "percent_encode_empty",               test_percent_encode_empty },
		{ "percent_encode_alphanumeric",        test_percent_encode_alphanumeric },
		{ "percent_encode_unreserved_chars",    test_percent_encode_unreserved_chars },
		{ "percent_encode_space",               test_percent_encode_space },
		{ "percent_encode_slash",               test_percent_encode_slash },
		{ "percent_encode_special_chars",       test_percent_encode_special_chars },
		{ "percent_encode_mixed",               test_percent_encode_mixed },
		/* build_fallback_uri */
		{ "fallback_uri_null_output_uri",       test_fallback_uri_null_output_uri },
		{ "fallback_uri_empty_output_uri",      test_fallback_uri_empty_output_uri },
		{ "fallback_uri_null_script_source",    test_fallback_uri_null_script_source },
		{ "fallback_uri_empty_script_source",   test_fallback_uri_empty_script_source },
		{ "fallback_uri_no_scheme",             test_fallback_uri_no_scheme },
		{ "fallback_uri_normal_https",          test_fallback_uri_normal_https },
		{ "fallback_uri_normal_http",           test_fallback_uri_normal_http },
		{ "fallback_uri_output_uri_no_path",    test_fallback_uri_output_uri_no_path },
		/* trim */
		{ "trim_null",                          test_trim_null },
		{ "trim_empty",                         test_trim_empty },
		{ "trim_no_whitespace",                 test_trim_no_whitespace },
		{ "trim_leading_and_trailing",          test_trim_leading_and_trailing },
		{ "trim_only_whitespace",               test_trim_only_whitespace },
		{ "trim_leading_only",                  test_trim_leading_only },
		{ "trim_trailing_only",                 test_trim_trailing_only },
		/* line_is_ignorable */
		{ "ignorable_null",                     test_ignorable_null },
		{ "ignorable_empty",                    test_ignorable_empty },
		{ "ignorable_comment",                  test_ignorable_comment },
		{ "ignorable_not_ignorable",            test_ignorable_not_ignorable },
		/* plan_dispatch */
		{ "plan_dispatch_null_plan",            test_plan_dispatch_null_plan },
		{ "plan_dispatch_argc_zero",            test_plan_dispatch_argc_zero },
		{ "plan_dispatch_argc_negative",        test_plan_dispatch_argc_negative },
		{ "plan_dispatch_argc_positive_null_argv", test_plan_dispatch_argc_positive_null_argv },
		{ "plan_dispatch_help",                 test_plan_dispatch_help },
		{ "plan_dispatch_set",                  test_plan_dispatch_set },
		{ "plan_dispatch_plain_command",        test_plan_dispatch_plain_command },
		{ "plan_dispatch_ela_prefix",           test_plan_dispatch_ela_prefix },
		{ "plan_dispatch_embedded_prefix",      test_plan_dispatch_embedded_linux_audit_prefix },
		{ "plan_dispatch_ela_alone_invalid",    test_plan_dispatch_ela_alone_invalid },
		{ "plan_dispatch_embedded_alone_invalid", test_plan_dispatch_embedded_alone_invalid },
		{ "plan_dispatch_null_errbuf_ok",       test_plan_dispatch_null_errbuf_ok },
		/* local_file_exists */
		{ "local_file_exists_null",             test_local_file_exists_null },
		{ "local_file_exists_empty",            test_local_file_exists_empty },
		{ "local_file_exists_nonexistent",      test_local_file_exists_nonexistent },
		{ "local_file_exists_directory",        test_local_file_exists_directory },
		{ "local_file_exists_real_file",        test_local_file_exists_real_file },
		/* create_temp_path */
		{ "create_temp_path_null_dir",          test_create_temp_path_null_dir },
		{ "create_temp_path_zero_dir_len",      test_create_temp_path_zero_dir_len },
		{ "create_temp_path_null_file",         test_create_temp_path_null_file },
		{ "create_temp_path_zero_file_len",     test_create_temp_path_zero_file_len },
		{ "create_temp_path_normal",            test_create_temp_path_normal },
		{ "create_temp_path_null_source",       test_create_temp_path_null_source_uses_default },
		{ "create_temp_path_file_buf_too_small", test_create_temp_path_file_buf_too_small },
	};

	return ela_run_test_suite("script_exec_util", cases, sizeof(cases) / sizeof(cases[0]));
}
