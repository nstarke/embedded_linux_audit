// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/remote_copy_util.h"

#include <string.h>

static void test_remote_copy_path_helpers_enforce_prefix_policy(void)
{
	ELA_ASSERT_TRUE(ela_has_path_prefix("/dev/ttyS0", "/dev"));
	ELA_ASSERT_FALSE(ela_has_path_prefix("/device", "/dev"));
	ELA_ASSERT_FALSE(ela_path_is_allowed("/proc/kmsg", false, false, false));
	ELA_ASSERT_TRUE(ela_path_is_allowed("/tmp/file", false, false, false));
}

static void test_remote_copy_stat_helper_accepts_copyable_types(void)
{
	struct stat st = {0};

	st.st_mode = S_IFREG;
	ELA_ASSERT_TRUE(ela_stat_is_copyable_file(&st));
	st.st_mode = S_IFCHR;
	ELA_ASSERT_TRUE(ela_stat_is_copyable_file(&st));
	st.st_mode = S_IFDIR;
	ELA_ASSERT_FALSE(ela_stat_is_copyable_file(&st));
}

static void test_remote_copy_summary_and_symlink_uri_helpers(void)
{
	char summary[256];
	char *uri;

	ELA_ASSERT_INT_EQ(0, ela_format_remote_copy_summary(summary, sizeof(summary), "/tmp/file", 2));
	ELA_ASSERT_STR_EQ("remote-copy copied path /tmp/file (2 files copied)\n", summary);

	uri = ela_remote_copy_build_symlink_upload_uri("https://ela.example/upload/file?path=%2Ftmp%2Flink", "../target path");
	ELA_ASSERT_TRUE(uri != NULL);
	ELA_ASSERT_TRUE(strstr(uri, "&symlink=true&symlinkPath=..%2Ftarget%20path") != NULL);
	free(uri);
}

int run_remote_copy_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "remote_copy_path_helpers_enforce_prefix_policy", test_remote_copy_path_helpers_enforce_prefix_policy },
		{ "remote_copy_stat_helper_accepts_copyable_types", test_remote_copy_stat_helper_accepts_copyable_types },
		{ "remote_copy_summary_and_symlink_uri_helpers", test_remote_copy_summary_and_symlink_uri_helpers },
	};

	return ela_run_test_suite("remote_copy_util", cases, sizeof(cases) / sizeof(cases[0]));
}
