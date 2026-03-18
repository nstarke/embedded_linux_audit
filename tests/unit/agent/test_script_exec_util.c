// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/shell/script_exec_util.h"

#include <stdlib.h>

static void test_script_exec_source_and_basename_helpers(void)
{
	ELA_ASSERT_TRUE(ela_script_is_http_source("https://ela.example/script.ela"));
	ELA_ASSERT_FALSE(ela_script_is_http_source("/tmp/script.ela"));
	ELA_ASSERT_STR_EQ("script.ela", ela_script_basename("/tmp/script.ela"));
}

static void test_script_exec_uri_and_trim_helpers(void)
{
	char spaced[] = " \t linux dmesg \n";
	char *uri = ela_script_build_fallback_uri("https://ela.example/api/data", "/tmp/fw script.ela");

	ELA_ASSERT_STR_EQ("linux dmesg", ela_script_trim(spaced));
	ELA_ASSERT_TRUE(uri != NULL);
	ELA_ASSERT_STR_EQ("https://ela.example/scripts/fw%20script.ela", uri);
	free(uri);
}

int run_script_exec_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "script_exec_source_and_basename_helpers", test_script_exec_source_and_basename_helpers },
		{ "script_exec_uri_and_trim_helpers", test_script_exec_uri_and_trim_helpers },
	};

	return ela_run_test_suite("script_exec_util", cases, sizeof(cases) / sizeof(cases[0]));
}
