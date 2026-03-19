// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ela_conf.h"
#include "../../../agent/net/ela_conf_util.h"

#include <string.h>

static void test_conf_trim_right_removes_trailing_whitespace(void)
{
	char line[] = "output-format=json \r\n";

	ela_conf_trim_right(line);
	ELA_ASSERT_STR_EQ("output-format=json", line);
}

static void test_conf_apply_line_updates_known_fields(void)
{
	struct ela_conf conf;

	memset(&conf, 0, sizeof(conf));
	ela_conf_apply_line(&conf, "remote=ws://agent.example/ws");
	ela_conf_apply_line(&conf, "output-http=https://ela.example/upload");
	ela_conf_apply_line(&conf, "output-format=json");
	ela_conf_apply_line(&conf, "insecure=true");

	ELA_ASSERT_STR_EQ("ws://agent.example/ws", conf.remote);
	ELA_ASSERT_STR_EQ("https://ela.example/upload", conf.output_http);
	ELA_ASSERT_STR_EQ("json", conf.output_format);
	ELA_ASSERT_INT_EQ(1, conf.insecure);
}

static void test_conf_string_is_true_accepts_supported_values(void)
{
	ELA_ASSERT_TRUE(ela_conf_string_is_true("true"));
	ELA_ASSERT_TRUE(ela_conf_string_is_true("1"));
	ELA_ASSERT_FALSE(ela_conf_string_is_true("false"));
	ELA_ASSERT_FALSE(ela_conf_string_is_true(NULL));
}

int run_ela_conf_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "conf_trim_right_removes_trailing_whitespace", test_conf_trim_right_removes_trailing_whitespace },
		{ "conf_apply_line_updates_known_fields", test_conf_apply_line_updates_known_fields },
		{ "conf_string_is_true_accepts_supported_values", test_conf_string_is_true_accepts_supported_values },
	};

	return ela_run_test_suite("ela_conf_util", cases, sizeof(cases) / sizeof(cases[0]));
}
