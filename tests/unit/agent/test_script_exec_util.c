// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/shell/script_exec_util.h"

#include <stdlib.h>
#include <string.h>

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

static void test_script_exec_dispatch_planner(void)
{
	struct ela_script_dispatch_plan plan;
	char errbuf[128];
	char *help_argv[] = { "help" };
	char *set_argv[] = { "set", "ELA_DEBUG", "true" };
	char *plain_argv[] = { "linux", "dmesg" };
	char *prefixed_argv[] = { "ela", "linux", "dmesg" };
	char *invalid_argv[] = { "ela" };

	ELA_ASSERT_TRUE(ela_script_line_is_ignorable(NULL));
	ELA_ASSERT_TRUE(ela_script_line_is_ignorable(""));
	ELA_ASSERT_TRUE(ela_script_line_is_ignorable("# comment"));
	ELA_ASSERT_FALSE(ela_script_line_is_ignorable("linux dmesg"));

	ELA_ASSERT_INT_EQ(0, ela_script_plan_dispatch(1, help_argv, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_SCRIPT_COMMAND_HELP, plan.kind);

	ELA_ASSERT_INT_EQ(0, ela_script_plan_dispatch(3, set_argv, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_SCRIPT_COMMAND_SET, plan.kind);

	ELA_ASSERT_INT_EQ(0, ela_script_plan_dispatch(2, plain_argv, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_SCRIPT_COMMAND_DISPATCH, plan.kind);
	ELA_ASSERT_INT_EQ(0, plan.script_cmd_idx);
	ELA_ASSERT_INT_EQ(3, plan.dispatch_argc);

	ELA_ASSERT_INT_EQ(0, ela_script_plan_dispatch(3, prefixed_argv, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, plan.script_cmd_idx);
	ELA_ASSERT_INT_EQ(3, plan.dispatch_argc);

	ELA_ASSERT_INT_EQ(-1, ela_script_plan_dispatch(1, invalid_argv, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "missing command") != NULL);
}

int run_script_exec_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "script_exec_source_and_basename_helpers", test_script_exec_source_and_basename_helpers },
		{ "script_exec_uri_and_trim_helpers", test_script_exec_uri_and_trim_helpers },
		{ "script_exec_dispatch_planner", test_script_exec_dispatch_planner },
	};

	return ela_run_test_suite("script_exec_util", cases, sizeof(cases) / sizeof(cases[0]));
}
