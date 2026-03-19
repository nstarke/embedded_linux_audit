// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/command_io_util.h"

#include <string.h>

static void test_execute_command_content_type_matches_format(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8", ela_execute_command_content_type("txt"));
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8", ela_execute_command_content_type("csv"));
	ELA_ASSERT_STR_EQ("application/json; charset=utf-8", ela_execute_command_content_type("json"));
}

static void test_parse_download_file_args_accepts_valid_inputs(void)
{
	char *argv[] = { "https://ela.example/file.bin", "/tmp/file.bin" };
	const char *url = NULL;
	const char *output = NULL;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_parse_download_file_args(2, argv, &url, &output, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ(argv[0], url);
	ELA_ASSERT_STR_EQ(argv[1], output);
}

static void test_parse_download_file_args_rejects_bad_inputs(void)
{
	char *argv[] = { "ftp://bad", "/tmp/file.bin", "extra" };
	const char *url = NULL;
	const char *output = NULL;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(-1, ela_parse_download_file_args(3, argv, &url, &output, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "http:// or https://") != NULL);
}

int run_command_io_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "execute_command_content_type_matches_format", test_execute_command_content_type_matches_format },
		{ "parse_download_file_args_accepts_valid_inputs", test_parse_download_file_args_accepts_valid_inputs },
		{ "parse_download_file_args_rejects_bad_inputs", test_parse_download_file_args_rejects_bad_inputs },
	};

	return ela_run_test_suite("command_io_util", cases, sizeof(cases) / sizeof(cases[0]));
}
