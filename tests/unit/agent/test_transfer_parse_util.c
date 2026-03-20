// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/transfer_parse_util.h"

#include <string.h>

/* -------------------------------------------------------------------------
 * ela_transfer_parse_args — null / minimal guard paths
 * ---------------------------------------------------------------------- */

static void test_parse_args_null_out(void)
{
	char *argv[] = { "transfer", "host:9000" };

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(2, argv, NULL, 3, NULL, NULL, 0));
}

static void test_parse_args_argc_too_small(void)
{
	char *argv[] = { "transfer" };
	struct ela_transfer_options opts;
	char errbuf[64] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(1, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "missing target") != NULL);
}

static void test_parse_args_no_target_after_flags(void)
{
	char *argv[] = { "transfer", "--insecure" };
	struct ela_transfer_options opts;
	char errbuf[64] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(2, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "missing target") != NULL);
}

/* -------------------------------------------------------------------------
 * ela_transfer_parse_args — help flag detection
 * ---------------------------------------------------------------------- */

static void test_parse_args_help_long(void)
{
	char *argv[] = { "transfer", "--help" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(2, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, opts.show_help);
}

static void test_parse_args_help_short(void)
{
	char *argv[] = { "transfer", "-h" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(2, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, opts.show_help);
}

/* -------------------------------------------------------------------------
 * ela_transfer_parse_args — target only (no flags)
 * ---------------------------------------------------------------------- */

static void test_parse_args_target_only(void)
{
	char *argv[] = { "transfer", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(2, argv, NULL, 5, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("host:9000", opts.target);
	ELA_ASSERT_INT_EQ(0, opts.insecure);
	ELA_ASSERT_INT_EQ(5, opts.retry_attempts);
}

static void test_parse_args_ws_target(void)
{
	char *argv[] = { "transfer", "wss://ela.example/ws" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(2, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("wss://ela.example/ws", opts.target);
}

/* -------------------------------------------------------------------------
 * ela_transfer_parse_args — --insecure flag
 * ---------------------------------------------------------------------- */

static void test_parse_args_insecure_flag(void)
{
	char *argv[] = { "transfer", "--insecure", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(3, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, opts.insecure);
	ELA_ASSERT_STR_EQ("host:9000", opts.target);
}

/* -------------------------------------------------------------------------
 * ela_transfer_parse_args — --retry-attempts (space-separated form)
 * ---------------------------------------------------------------------- */

static void test_parse_args_retry_space_valid(void)
{
	char *argv[] = { "transfer", "--retry-attempts", "7", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(4, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(7, opts.retry_attempts);
}

static void test_parse_args_retry_space_missing_value(void)
{
	char *argv[] = { "transfer", "--retry-attempts" };
	struct ela_transfer_options opts;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(2, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "invalid value") != NULL);
}

static void test_parse_args_retry_space_invalid_value(void)
{
	char *argv[] = { "transfer", "--retry-attempts", "bad", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(4, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "invalid value") != NULL);
}

/* -------------------------------------------------------------------------
 * ela_transfer_parse_args — --retry-attempts= (equals form)
 * ---------------------------------------------------------------------- */

static void test_parse_args_retry_equals_valid(void)
{
	char *argv[] = { "transfer", "--retry-attempts=7", "wss://ela.example/ws" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(3, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(7, opts.retry_attempts);
	ELA_ASSERT_STR_EQ("wss://ela.example/ws", opts.target);
}

static void test_parse_args_retry_equals_invalid(void)
{
	char *argv[] = { "transfer", "--retry-attempts=abc", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(3, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "invalid value") != NULL);
}

static void test_parse_args_retry_equals_negative(void)
{
	char *argv[] = { "transfer", "--retry-attempts=-1", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(3, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
}

static void test_parse_args_retry_equals_too_large(void)
{
	char *argv[] = { "transfer", "--retry-attempts=1001", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(3, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
}

static void test_parse_args_retry_boundary_zero(void)
{
	char *argv[] = { "transfer", "--retry-attempts=0", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(3, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(0, opts.retry_attempts);
}

static void test_parse_args_retry_boundary_max(void)
{
	char *argv[] = { "transfer", "--retry-attempts=1000", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(3, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1000, opts.retry_attempts);
}

/* -------------------------------------------------------------------------
 * ela_transfer_parse_args — env_retry_attempts override
 * ---------------------------------------------------------------------- */

static void test_parse_args_env_overrides_default(void)
{
	char *argv[] = { "transfer", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(2, argv, "9", 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(9, opts.retry_attempts);
}

static void test_parse_args_env_invalid_uses_default(void)
{
	char *argv[] = { "transfer", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[64];

	/* invalid env value — silently ignored, default_retry_attempts used */
	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(2, argv, "bad", 5, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(5, opts.retry_attempts);
}

static void test_parse_args_env_null_uses_default(void)
{
	char *argv[] = { "transfer", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(2, argv, NULL, 5, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(5, opts.retry_attempts);
}

static void test_parse_args_env_empty_uses_default(void)
{
	char *argv[] = { "transfer", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(2, argv, "", 5, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(5, opts.retry_attempts);
}

static void test_parse_args_explicit_flag_overrides_env(void)
{
	char *argv[] = { "transfer", "--retry-attempts=12", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(3, argv, "9", 5, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(12, opts.retry_attempts);
}

/* -------------------------------------------------------------------------
 * ela_transfer_parse_args — combined flags
 * ---------------------------------------------------------------------- */

static void test_parse_args_accepts_flags_and_target(void)
{
	char *argv[] = { "transfer", "--insecure", "--retry-attempts=7", "wss://ela.example/ws" };
	struct ela_transfer_options opts;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(4, argv, "3", 5, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, opts.insecure);
	ELA_ASSERT_INT_EQ(7, opts.retry_attempts);
	ELA_ASSERT_STR_EQ("wss://ela.example/ws", opts.target);
}

static void test_parse_args_flags_before_and_after_target(void)
{
	char *argv[] = { "transfer", "--insecure", "host:9000", "--retry-attempts=2" };
	struct ela_transfer_options opts;
	char errbuf[64];

	ELA_ASSERT_INT_EQ(0, ela_transfer_parse_args(4, argv, NULL, 5, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, opts.insecure);
	ELA_ASSERT_INT_EQ(2, opts.retry_attempts);
	ELA_ASSERT_STR_EQ("host:9000", opts.target);
}

/* -------------------------------------------------------------------------
 * ela_transfer_parse_args — unknown option / extra arg rejection
 * ---------------------------------------------------------------------- */

static void test_parse_args_unknown_option(void)
{
	char *argv[] = { "transfer", "--unknown", "host:9000" };
	struct ela_transfer_options opts;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(3, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "unknown option") != NULL);
}

static void test_parse_args_extra_argument(void)
{
	char *argv[] = { "transfer", "host:9000", "extra" };
	struct ela_transfer_options opts;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(3, argv, NULL, 3, &opts, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "unexpected argument") != NULL);
}

/* -------------------------------------------------------------------------
 * ela_transfer_parse_args — null errbuf resilience
 * ---------------------------------------------------------------------- */

static void test_parse_args_null_errbuf_no_crash_on_error(void)
{
	char *argv[] = { "transfer", "--unknown" };
	struct ela_transfer_options opts;

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(2, argv, NULL, 3, &opts, NULL, 0));
}

static void test_parse_args_null_errbuf_argc_too_small(void)
{
	char *argv[] = { "transfer" };
	struct ela_transfer_options opts;

	ELA_ASSERT_INT_EQ(-1, ela_transfer_parse_args(1, argv, NULL, 3, &opts, NULL, 0));
}

/* =========================================================================
 * Test suite registration
 * ====================================================================== */

int run_transfer_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* null / guard paths */
		{ "parse_args_null_out",                    test_parse_args_null_out },
		{ "parse_args_argc_too_small",              test_parse_args_argc_too_small },
		{ "parse_args_no_target_after_flags",       test_parse_args_no_target_after_flags },
		/* help detection */
		{ "parse_args_help_long",                   test_parse_args_help_long },
		{ "parse_args_help_short",                  test_parse_args_help_short },
		/* target only */
		{ "parse_args_target_only",                 test_parse_args_target_only },
		{ "parse_args_ws_target",                   test_parse_args_ws_target },
		/* insecure flag */
		{ "parse_args_insecure_flag",               test_parse_args_insecure_flag },
		/* retry-attempts space form */
		{ "parse_args_retry_space_valid",           test_parse_args_retry_space_valid },
		{ "parse_args_retry_space_missing_value",   test_parse_args_retry_space_missing_value },
		{ "parse_args_retry_space_invalid_value",   test_parse_args_retry_space_invalid_value },
		/* retry-attempts equals form */
		{ "parse_args_retry_equals_valid",          test_parse_args_retry_equals_valid },
		{ "parse_args_retry_equals_invalid",        test_parse_args_retry_equals_invalid },
		{ "parse_args_retry_equals_negative",       test_parse_args_retry_equals_negative },
		{ "parse_args_retry_equals_too_large",      test_parse_args_retry_equals_too_large },
		{ "parse_args_retry_boundary_zero",         test_parse_args_retry_boundary_zero },
		{ "parse_args_retry_boundary_max",          test_parse_args_retry_boundary_max },
		/* env override */
		{ "parse_args_env_overrides_default",       test_parse_args_env_overrides_default },
		{ "parse_args_env_invalid_uses_default",    test_parse_args_env_invalid_uses_default },
		{ "parse_args_env_null_uses_default",       test_parse_args_env_null_uses_default },
		{ "parse_args_env_empty_uses_default",      test_parse_args_env_empty_uses_default },
		{ "parse_args_explicit_overrides_env",      test_parse_args_explicit_flag_overrides_env },
		/* combined flags */
		{ "parse_args_accepts_flags_and_target",    test_parse_args_accepts_flags_and_target },
		{ "parse_args_flags_before_and_after_target", test_parse_args_flags_before_and_after_target },
		/* rejection */
		{ "parse_args_unknown_option",              test_parse_args_unknown_option },
		{ "parse_args_extra_argument",              test_parse_args_extra_argument },
		/* null errbuf resilience */
		{ "parse_args_null_errbuf_on_error",        test_parse_args_null_errbuf_no_crash_on_error },
		{ "parse_args_null_errbuf_argc_small",      test_parse_args_null_errbuf_argc_too_small },
	};

	return ela_run_test_suite("transfer_parse_util",
				  cases, sizeof(cases) / sizeof(cases[0]));
}
