// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/dispatch_util.h"

#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * ela_build_command_summary tests
 * ====================================================================== */

static void test_summary_null_argv(void)
{
	char *s = ela_build_command_summary(3, NULL, 1);
	ELA_ASSERT_STR_EQ("interactive", s);
	free(s);
}

static void test_summary_start_idx_negative(void)
{
	char *argv[] = { "prog", "cmd" };
	char *s = ela_build_command_summary(2, argv, -1);
	ELA_ASSERT_STR_EQ("interactive", s);
	free(s);
}

static void test_summary_start_idx_equals_argc(void)
{
	char *argv[] = { "prog" };
	char *s = ela_build_command_summary(1, argv, 1);
	ELA_ASSERT_STR_EQ("interactive", s);
	free(s);
}

static void test_summary_start_idx_beyond_argc(void)
{
	char *argv[] = { "prog", "cmd" };
	char *s = ela_build_command_summary(2, argv, 5);
	ELA_ASSERT_STR_EQ("interactive", s);
	free(s);
}

static void test_summary_single_arg(void)
{
	char *argv[] = { "prog", "linux" };
	char *s = ela_build_command_summary(2, argv, 1);
	ELA_ASSERT_STR_EQ("linux", s);
	free(s);
}

static void test_summary_two_args(void)
{
	char *argv[] = { "prog", "linux", "scan" };
	char *s = ela_build_command_summary(3, argv, 1);
	ELA_ASSERT_STR_EQ("linux scan", s);
	free(s);
}

static void test_summary_three_args(void)
{
	char *argv[] = { "prog", "uboot", "env", "read" };
	char *s = ela_build_command_summary(4, argv, 1);
	ELA_ASSERT_STR_EQ("uboot env read", s);
	free(s);
}

static void test_summary_start_at_second_arg(void)
{
	char *argv[] = { "prog", "linux", "download-file", "/tmp/foo" };
	char *s = ela_build_command_summary(4, argv, 2);
	ELA_ASSERT_STR_EQ("download-file /tmp/foo", s);
	free(s);
}

static void test_summary_start_at_last_arg(void)
{
	char *argv[] = { "prog", "cmd", "sub" };
	char *s = ela_build_command_summary(3, argv, 2);
	ELA_ASSERT_STR_EQ("sub", s);
	free(s);
}

/* =========================================================================
 * ela_command_should_emit_lifecycle_events tests
 * ====================================================================== */

static void test_lifecycle_script_path_set(void)
{
	char *argv[] = { "prog" };
	ELA_ASSERT_TRUE(ela_command_should_emit_lifecycle_events(
		1, argv, 0, "/path/to/script.sh"));
}

static void test_lifecycle_script_path_empty_string(void)
{
	/* empty string is falsy — treated same as no script */
	char *argv[] = { "prog", "linux", "scan" };
	ELA_ASSERT_TRUE(ela_command_should_emit_lifecycle_events(
		3, argv, 1, ""));
}

static void test_lifecycle_null_argv(void)
{
	ELA_ASSERT_TRUE(ela_command_should_emit_lifecycle_events(
		3, NULL, 1, NULL));
}

static void test_lifecycle_cmd_idx_out_of_range(void)
{
	char *argv[] = { "prog" };
	ELA_ASSERT_TRUE(ela_command_should_emit_lifecycle_events(
		1, argv, 5, NULL));
}

static void test_lifecycle_linux_download_file_false(void)
{
	char *argv[] = { "prog", "linux", "download-file" };
	ELA_ASSERT_FALSE(ela_command_should_emit_lifecycle_events(
		3, argv, 1, NULL));
}

static void test_lifecycle_linux_list_files_false(void)
{
	char *argv[] = { "prog", "linux", "list-files" };
	ELA_ASSERT_FALSE(ela_command_should_emit_lifecycle_events(
		3, argv, 1, NULL));
}

static void test_lifecycle_linux_list_symlinks_false(void)
{
	char *argv[] = { "prog", "linux", "list-symlinks" };
	ELA_ASSERT_FALSE(ela_command_should_emit_lifecycle_events(
		3, argv, 1, NULL));
}

static void test_lifecycle_linux_remote_copy_false(void)
{
	char *argv[] = { "prog", "linux", "remote-copy" };
	ELA_ASSERT_FALSE(ela_command_should_emit_lifecycle_events(
		3, argv, 1, NULL));
}

static void test_lifecycle_linux_scan_true(void)
{
	char *argv[] = { "prog", "linux", "scan" };
	ELA_ASSERT_TRUE(ela_command_should_emit_lifecycle_events(
		3, argv, 1, NULL));
}

static void test_lifecycle_linux_no_subcommand_true(void)
{
	char *argv[] = { "prog", "linux" };
	ELA_ASSERT_TRUE(ela_command_should_emit_lifecycle_events(
		2, argv, 1, NULL));
}

static void test_lifecycle_uboot_cmd_true(void)
{
	char *argv[] = { "prog", "uboot", "env" };
	ELA_ASSERT_TRUE(ela_command_should_emit_lifecycle_events(
		3, argv, 1, NULL));
}

static void test_lifecycle_download_file_wrong_group_true(void)
{
	/* "download-file" subcommand only suppresses under "linux" group */
	char *argv[] = { "prog", "other", "download-file" };
	ELA_ASSERT_TRUE(ela_command_should_emit_lifecycle_events(
		3, argv, 1, NULL));
}

static void test_lifecycle_script_overrides_suppressed_subcommand(void)
{
	/* script_path set → always emit, even for normally-suppressed subcommands */
	char *argv[] = { "prog", "linux", "download-file" };
	ELA_ASSERT_TRUE(ela_command_should_emit_lifecycle_events(
		3, argv, 1, "myscript.sh"));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_dispatch_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "summary/null_argv",               test_summary_null_argv },
		{ "summary/start_idx_negative",      test_summary_start_idx_negative },
		{ "summary/start_idx_equals_argc",   test_summary_start_idx_equals_argc },
		{ "summary/start_idx_beyond_argc",   test_summary_start_idx_beyond_argc },
		{ "summary/single_arg",              test_summary_single_arg },
		{ "summary/two_args",                test_summary_two_args },
		{ "summary/three_args",              test_summary_three_args },
		{ "summary/start_at_second_arg",     test_summary_start_at_second_arg },
		{ "summary/start_at_last_arg",       test_summary_start_at_last_arg },
		{ "lifecycle/script_path_set",       test_lifecycle_script_path_set },
		{ "lifecycle/script_path_empty",     test_lifecycle_script_path_empty_string },
		{ "lifecycle/null_argv",             test_lifecycle_null_argv },
		{ "lifecycle/cmd_idx_out_of_range",  test_lifecycle_cmd_idx_out_of_range },
		{ "lifecycle/download-file_false",   test_lifecycle_linux_download_file_false },
		{ "lifecycle/list-files_false",      test_lifecycle_linux_list_files_false },
		{ "lifecycle/list-symlinks_false",   test_lifecycle_linux_list_symlinks_false },
		{ "lifecycle/remote-copy_false",     test_lifecycle_linux_remote_copy_false },
		{ "lifecycle/linux_scan_true",       test_lifecycle_linux_scan_true },
		{ "lifecycle/linux_no_sub_true",     test_lifecycle_linux_no_subcommand_true },
		{ "lifecycle/uboot_true",            test_lifecycle_uboot_cmd_true },
		{ "lifecycle/wrong_group_true",      test_lifecycle_download_file_wrong_group_true },
		{ "lifecycle/script_overrides_sup",  test_lifecycle_script_overrides_suppressed_subcommand },
	};
	return ela_run_test_suite("dispatch_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
