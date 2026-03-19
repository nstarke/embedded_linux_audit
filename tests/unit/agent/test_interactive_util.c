// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/shell/interactive_util.h"

#include <stdlib.h>
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

static void test_interactive_set_command_planner(void)
{
	struct ela_interactive_set_plan plan;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command("ELA_API_URL",
							      "https://ela.example/api",
							      &plan,
							      errbuf,
							      sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_API_URL, plan.kind);
	ELA_ASSERT_TRUE(plan.clear_output_overrides);
	ELA_ASSERT_TRUE(plan.update_conf);
	ELA_ASSERT_STR_EQ("ELA_API_URL", plan.display_name);

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command("ELA_OUTPUT_HTTP",
							      "https://ela.example/upload",
							      &plan,
							      errbuf,
							      sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("ELA_OUTPUT_HTTPS", plan.primary_env_name);
	ELA_ASSERT_STR_EQ("ELA_OUTPUT_HTTP", plan.unset_env_name);

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command("ELA_API_KEY",
							      "secret",
							      &plan,
							      errbuf,
							      sizeof(errbuf)));
	ELA_ASSERT_TRUE(plan.redact_value);

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command("ELA_OUTPUT_FORMAT",
							       "yaml",
							       &plan,
							       errbuf,
							       sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid ELA_OUTPUT_FORMAT") != NULL);
}

static void test_interactive_prompt_history_and_completion_helpers(void)
{
	char prompt[128];
	struct ela_interactive_history history = {0};
	const char *matches[8];
	size_t match_count;

	ELA_ASSERT_TRUE(ela_interactive_should_show_prompt(0, NULL));
	ELA_ASSERT_TRUE(ela_interactive_should_show_prompt(-1, "aa:bb"));
	ELA_ASSERT_FALSE(ela_interactive_should_show_prompt(-1, ""));
	ELA_ASSERT_TRUE(ela_interactive_is_exit_command("quit"));
	ELA_ASSERT_TRUE(ela_interactive_is_help_command("help"));

	ELA_ASSERT_INT_EQ(0, ela_interactive_build_prompt(prompt, sizeof(prompt),
							  "/usr/bin/ela",
							  "aa:bb",
							  true));
	ELA_ASSERT_STR_EQ("(aa:bb)> ", prompt);

	ELA_ASSERT_INT_EQ(0, ela_interactive_history_add(&history, "linux dmesg"));
	ELA_ASSERT_INT_EQ(0, ela_interactive_history_add(&history, ""));
	ELA_ASSERT_INT_EQ(1, history.count);
	ELA_ASSERT_STR_EQ("linux dmesg", history.entries[0]);

	match_count = ela_interactive_collect_matches(
		ela_interactive_candidates_for_position(2, (char *[]){"linux", "d"}),
		"d",
		matches,
		8);
	ELA_ASSERT_INT_EQ(2, (int)match_count);
	ELA_ASSERT_STR_EQ("dmesg", matches[0]);
	ELA_ASSERT_STR_EQ("download-file", matches[1]);

	ela_interactive_history_free(&history);
}

int run_interactive_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "interactive_candidates_helper", test_interactive_candidates_helper },
		{ "interactive_supported_variables_formatter", test_interactive_supported_variables_formatter },
		{ "interactive_set_command_planner", test_interactive_set_command_planner },
		{ "interactive_prompt_history_and_completion_helpers", test_interactive_prompt_history_and_completion_helpers },
	};

	return ela_run_test_suite("interactive_util", cases, sizeof(cases) / sizeof(cases[0]));
}
