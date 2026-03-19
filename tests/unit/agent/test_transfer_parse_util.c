// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/transfer_parse_util.h"

#include <string.h>

static void test_transfer_parse_args_accepts_flags_and_target(void)
{
	char *argv[] = { "transfer", "--insecure", "--retry-attempts=7", "wss://ela.example/ws" };
	struct ela_transfer_options options;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(4, argv, "3", 5, &options, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, options.insecure);
	ELA_ASSERT_INT_EQ(7, options.retry_attempts);
	ELA_ASSERT_STR_EQ("wss://ela.example/ws", options.target);
}

static void test_transfer_parse_args_uses_env_default_and_help(void)
{
	char *argv[] = { "transfer", "--help" };
	struct ela_transfer_options options;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(2, argv, "9", 5, &options, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, options.show_help);

	argv[1] = "host:9000";
	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(2, argv, "9", 5, &options, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(9, options.retry_attempts);
	ELA_ASSERT_STR_EQ("host:9000", options.target);
}

static void test_transfer_parse_args_rejects_bad_inputs(void)
{
	char *argv[] = { "transfer", "--retry-attempts", "bad", "host:9000" };
	struct ela_transfer_options options;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(4, argv, NULL, 5, &options, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "invalid value") != NULL);

	argv[1] = "--unknown";
	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(2, argv, NULL, 5, &options, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "unknown option") != NULL);
}

int run_transfer_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "transfer_parse_args_accepts_flags_and_target", test_transfer_parse_args_accepts_flags_and_target },
		{ "transfer_parse_args_uses_env_default_and_help", test_transfer_parse_args_uses_env_default_and_help },
		{ "transfer_parse_args_rejects_bad_inputs", test_transfer_parse_args_rejects_bad_inputs },
	};

	return ela_run_test_suite("transfer_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
