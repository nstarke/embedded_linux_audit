// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/shell/interactive_util.h"

#include <string.h>

static void test_interactive_candidates_helper(void)
{
	char *argv0[] = { "linux" };
	char *argv1[] = { "set", "ELA_" };
	const char *const *candidates;

	candidates = ela_interactive_candidates_for_position(1, argv0);
	ELA_ASSERT_STR_EQ("help", candidates[0]);

	candidates = ela_interactive_candidates_for_position(2, argv0);
	ELA_ASSERT_STR_EQ("dmesg", candidates[0]);

	candidates = ela_interactive_candidates_for_position(2, argv1);
	ELA_ASSERT_STR_EQ("ELA_API_URL", candidates[0]);
}

static void test_interactive_supported_variables_formatter(void)
{
	char buf[2048];

	ELA_ASSERT_INT_EQ(0, ela_interactive_format_supported_variables(buf, sizeof(buf),
									 "https://ela.example",
									 "true",
									 NULL,
									 "json",
									 "127.0.0.1:9000",
									 "./script.ela",
									 NULL,
									 "false",
									 "secret",
									 "true",
									 NULL,
									 "5"));
	ELA_ASSERT_TRUE(strstr(buf, "ELA_API_URL              current=https://ela.example") != NULL);
	ELA_ASSERT_TRUE(strstr(buf, "ELA_API_KEY              current=<set>") != NULL);
	ELA_ASSERT_TRUE(strstr(buf, "ELA_DEBUG                current=<unset>") != NULL);
}

int run_interactive_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "interactive_candidates_helper", test_interactive_candidates_helper },
		{ "interactive_supported_variables_formatter", test_interactive_supported_variables_formatter },
	};

	return ela_run_test_suite("interactive_util", cases, sizeof(cases) / sizeof(cases[0]));
}
