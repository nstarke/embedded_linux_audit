// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/dispatch_parse_util.h"

#include <stdbool.h>
#include <string.h>

/* =========================================================================
 * Helpers
 * ====================================================================== */

static int parse(int argc, char **argv,
		 const struct ela_dispatch_env *env,
		 struct ela_dispatch_opts *opts,
		 char *errbuf, size_t errbuf_len)
{
	return ela_dispatch_parse_args(argc, argv, env, opts, errbuf, errbuf_len);
}

static struct ela_dispatch_env empty_env(void)
{
	struct ela_dispatch_env e;
	memset(&e, 0, sizeof(e));
	return e;
}

/* =========================================================================
 * Null / degenerate guards
 * ====================================================================== */

static void test_null_opts(void)
{
	char *argv[] = { "prog" };
	int rc = parse(1, argv, NULL, NULL, NULL, 0);
	ELA_ASSERT_INT_EQ(2, rc);
}

static void test_no_args_defaults(void)
{
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("txt", opts.output_format);
	ELA_ASSERT_INT_EQ(ELA_DISPATCH_DEFAULT_RETRY_ATTEMPTS, opts.retry_attempts);
	ELA_ASSERT_TRUE(opts.verbose);
	ELA_ASSERT_FALSE(opts.insecure);
	ELA_ASSERT_FALSE(opts.show_help);
	ELA_ASSERT_INT_EQ(1, opts.cmd_idx);
}

/* =========================================================================
 * Help flags
 * ====================================================================== */

static void test_help_short(void)
{
	char *argv[] = { "prog", "-h" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.show_help);
}

static void test_help_long(void)
{
	char *argv[] = { "prog", "--help" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.show_help);
}

static void test_help_word(void)
{
	char *argv[] = { "prog", "help" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.show_help);
}

/* =========================================================================
 * --quiet
 * ====================================================================== */

static void test_quiet_flag(void)
{
	char *argv[] = { "prog", "--quiet" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_FALSE(opts.verbose);
}

/* =========================================================================
 * --insecure
 * ====================================================================== */

static void test_insecure_flag(void)
{
	char *argv[] = { "prog", "--insecure" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.insecure);
}

/* =========================================================================
 * --output-format
 * ====================================================================== */

static void test_output_format_space(void)
{
	char *argv[] = { "prog", "--output-format", "csv" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("csv", opts.output_format);
	ELA_ASSERT_TRUE(opts.output_format_explicit);
}

static void test_output_format_equals(void)
{
	char *argv[] = { "prog", "--output-format=json" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("json", opts.output_format);
	ELA_ASSERT_TRUE(opts.output_format_explicit);
}

static void test_output_format_missing_value(void)
{
	char errbuf[256] = {0};
	char *argv[] = { "prog", "--output-format" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, errbuf, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(2, rc);
	ELA_ASSERT_TRUE(strlen(errbuf) > 0);
}

/* =========================================================================
 * --output-tcp
 * ====================================================================== */

static void test_output_tcp_space(void)
{
	char *argv[] = { "prog", "--output-tcp", "10.0.0.1:9000" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("10.0.0.1:9000", opts.output_tcp);
	ELA_ASSERT_TRUE(opts.output_explicit);
}

static void test_output_tcp_equals(void)
{
	char *argv[] = { "prog", "--output-tcp=10.0.0.2:8080" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("10.0.0.2:8080", opts.output_tcp);
}

static void test_output_tcp_missing_value(void)
{
	char errbuf[256] = {0};
	char *argv[] = { "prog", "--output-tcp" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, errbuf, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(2, rc);
}

/* =========================================================================
 * --output-http
 * ====================================================================== */

static void test_output_http_http_url(void)
{
	char *argv[] = { "prog", "--output-http", "http://host:8080/api" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.output_http != NULL && strlen(opts.output_http) > 0);
	ELA_ASSERT_TRUE(opts.output_https == NULL || strlen(opts.output_https) == 0);
	ELA_ASSERT_TRUE(opts.output_explicit);
}

static void test_output_http_https_url(void)
{
	char *argv[] = { "prog", "--output-http", "https://host/api" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.output_https != NULL && strlen(opts.output_https) > 0);
	ELA_ASSERT_TRUE(opts.output_http == NULL || strlen(opts.output_http) == 0);
}

static void test_output_http_equals_form(void)
{
	char *argv[] = { "prog", "--output-http=http://host/api" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.output_http != NULL);
}

static void test_output_http_missing_value(void)
{
	char errbuf[256] = {0};
	char *argv[] = { "prog", "--output-http" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, errbuf, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(2, rc);
}

/* =========================================================================
 * --script
 * ====================================================================== */

static void test_script_space(void)
{
	char *argv[] = { "prog", "--script", "/etc/ela/run.sh" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("/etc/ela/run.sh", opts.script_path);
}

static void test_script_equals(void)
{
	char *argv[] = { "prog", "--script=/etc/ela/run.sh" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("/etc/ela/run.sh", opts.script_path);
}

static void test_script_missing_value(void)
{
	char errbuf[256] = {0};
	char *argv[] = { "prog", "--script" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, errbuf, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(2, rc);
}

/* =========================================================================
 * --remote
 * ====================================================================== */

static void test_remote_space(void)
{
	char *argv[] = { "prog", "--remote", "192.168.1.1:22" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("192.168.1.1:22", opts.remote_target);
	ELA_ASSERT_TRUE(opts.conf_needs_save);
}

static void test_remote_equals(void)
{
	char *argv[] = { "prog", "--remote=host:22" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("host:22", opts.remote_target);
	ELA_ASSERT_TRUE(opts.conf_needs_save);
}

static void test_remote_missing_value(void)
{
	char errbuf[256] = {0};
	char *argv[] = { "prog", "--remote" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, errbuf, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(2, rc);
}

/* =========================================================================
 * --retry-attempts
 * ====================================================================== */

static void test_retry_space_valid(void)
{
	char *argv[] = { "prog", "--retry-attempts", "3" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_INT_EQ(3, opts.retry_attempts);
}

static void test_retry_equals_valid(void)
{
	char *argv[] = { "prog", "--retry-attempts=10" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_INT_EQ(10, opts.retry_attempts);
}

static void test_retry_zero_valid(void)
{
	char *argv[] = { "prog", "--retry-attempts", "0" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_INT_EQ(0, opts.retry_attempts);
}

static void test_retry_boundary_1000(void)
{
	char *argv[] = { "prog", "--retry-attempts", "1000" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_INT_EQ(1000, opts.retry_attempts);
}

static void test_retry_over_limit(void)
{
	char errbuf[256] = {0};
	char *argv[] = { "prog", "--retry-attempts", "1001" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, errbuf, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(2, rc);
}

static void test_retry_negative(void)
{
	char errbuf[256] = {0};
	char *argv[] = { "prog", "--retry-attempts", "-1" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, errbuf, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(2, rc);
}

static void test_retry_non_numeric(void)
{
	char errbuf[256] = {0};
	char *argv[] = { "prog", "--retry-attempts", "abc" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, errbuf, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(2, rc);
}

static void test_retry_missing_value(void)
{
	char errbuf[256] = {0};
	char *argv[] = { "prog", "--retry-attempts" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, errbuf, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(2, rc);
}

/* =========================================================================
 * --api-key
 * ====================================================================== */

static void test_api_key_space(void)
{
	char *argv[] = { "prog", "--api-key", "mykey123" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("mykey123", opts.api_key);
}

static void test_api_key_equals(void)
{
	char *argv[] = { "prog", "--api-key=secret" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("secret", opts.api_key);
}

static void test_api_key_missing_value(void)
{
	char errbuf[256] = {0};
	char *argv[] = { "prog", "--api-key" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, NULL, &opts, errbuf, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(2, rc);
}

/* =========================================================================
 * cmd_idx — non-flag argument stops global parsing
 * ====================================================================== */

static void test_cmd_idx_subcommand(void)
{
	char *argv[] = { "prog", "linux", "scan" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_INT_EQ(1, opts.cmd_idx);
}

static void test_cmd_idx_after_flags(void)
{
	char *argv[] = { "prog", "--quiet", "--insecure", "uboot" };
	struct ela_dispatch_opts opts;
	int rc = parse(4, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_INT_EQ(3, opts.cmd_idx);
	ELA_ASSERT_FALSE(opts.verbose);
	ELA_ASSERT_TRUE(opts.insecure);
}

/* =========================================================================
 * Environment variable defaults
 * ====================================================================== */

static void test_env_output_format_default(void)
{
	struct ela_dispatch_env env = empty_env();
	env.output_format = "csv";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("csv", opts.output_format);
	ELA_ASSERT_FALSE(opts.output_format_explicit);
}

static void test_env_output_format_cli_overrides(void)
{
	struct ela_dispatch_env env = empty_env();
	env.output_format = "csv";
	char *argv[] = { "prog", "--output-format=json" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("json", opts.output_format);
	ELA_ASSERT_TRUE(opts.output_format_explicit);
}

static void test_env_quiet(void)
{
	struct ela_dispatch_env env = empty_env();
	env.quiet = "1";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_FALSE(opts.verbose);
}

static void test_env_quiet_true(void)
{
	struct ela_dispatch_env env = empty_env();
	env.quiet = "true";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_FALSE(opts.verbose);
}

static void test_env_quiet_yes(void)
{
	struct ela_dispatch_env env = empty_env();
	env.quiet = "yes";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_FALSE(opts.verbose);
}

static void test_env_quiet_on(void)
{
	struct ela_dispatch_env env = empty_env();
	env.quiet = "on";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_FALSE(opts.verbose);
}

static void test_env_quiet_other_value_verbose(void)
{
	struct ela_dispatch_env env = empty_env();
	env.quiet = "0";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.verbose);
}

static void test_env_insecure(void)
{
	struct ela_dispatch_env env = empty_env();
	env.output_insecure = "1";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.insecure);
}

static void test_env_ws_retry(void)
{
	struct ela_dispatch_env env = empty_env();
	env.ws_retry = "7";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_INT_EQ(7, opts.retry_attempts);
}

static void test_env_ws_retry_invalid_keeps_default(void)
{
	struct ela_dispatch_env env = empty_env();
	env.ws_retry = "bad";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_INT_EQ(ELA_DISPATCH_DEFAULT_RETRY_ATTEMPTS, opts.retry_attempts);
}

static void test_env_output_tcp(void)
{
	struct ela_dispatch_env env = empty_env();
	env.output_tcp = "10.0.0.5:9000";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("10.0.0.5:9000", opts.output_tcp);
}

static void test_env_api_url_fallback_http(void)
{
	struct ela_dispatch_env env = empty_env();
	env.api_url = "http://api.example.com/v1";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.output_http != NULL && strlen(opts.output_http) > 0);
}

static void test_env_api_url_fallback_https(void)
{
	struct ela_dispatch_env env = empty_env();
	env.api_url = "https://api.example.com/v1";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.output_https != NULL && strlen(opts.output_https) > 0);
}

static void test_env_api_url_not_applied_when_http_already_set(void)
{
	struct ela_dispatch_env env = empty_env();
	env.api_url = "http://api.example.com/v1";
	char *argv[] = { "prog", "--output-http=http://custom.host/api" };
	struct ela_dispatch_opts opts;
	int rc = parse(2, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	/* The CLI-set value should win, not the api_url fallback */
	ELA_ASSERT_TRUE(opts.output_http != NULL);
}

static void test_env_api_insecure(void)
{
	struct ela_dispatch_env env = empty_env();
	env.api_insecure = "true";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(opts.insecure);
}

static void test_env_script_fallback(void)
{
	struct ela_dispatch_env env = empty_env();
	env.script = "/etc/ela/default.sh";
	char *argv[] = { "prog" };
	struct ela_dispatch_opts opts;
	int rc = parse(1, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ("/etc/ela/default.sh", opts.script_path);
}

static void test_env_script_not_applied_when_cmd_present(void)
{
	struct ela_dispatch_env env = empty_env();
	env.script = "/etc/ela/default.sh";
	char *argv[] = { "prog", "linux", "scan" };
	struct ela_dispatch_opts opts;
	int rc = parse(3, argv, &env, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	/* cmd_idx < argc, so script fallback should NOT apply */
	ELA_ASSERT_TRUE(opts.script_path == NULL);
}

/* =========================================================================
 * Combined flags
 * ====================================================================== */

static void test_combined_flags(void)
{
	char *argv[] = {
		"prog",
		"--quiet",
		"--insecure",
		"--output-format=csv",
		"--retry-attempts=2",
		"--api-key=k",
		"linux",
	};
	struct ela_dispatch_opts opts;
	int rc = parse(7, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_FALSE(opts.verbose);
	ELA_ASSERT_TRUE(opts.insecure);
	ELA_ASSERT_STR_EQ("csv", opts.output_format);
	ELA_ASSERT_INT_EQ(2, opts.retry_attempts);
	ELA_ASSERT_STR_EQ("k", opts.api_key);
	ELA_ASSERT_INT_EQ(6, opts.cmd_idx);
}

static void test_null_errbuf_no_crash(void)
{
	char *argv[] = { "prog", "--output-format" };
	struct ela_dispatch_opts opts;
	/* errbuf=NULL, errbuf_len=0 must not crash */
	int rc = parse(2, argv, NULL, &opts, NULL, 0);
	ELA_ASSERT_INT_EQ(2, rc);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_dispatch_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "null_opts",                          test_null_opts },
		{ "no_args_defaults",                   test_no_args_defaults },
		{ "help/-h",                            test_help_short },
		{ "help/--help",                        test_help_long },
		{ "help/word",                          test_help_word },
		{ "quiet/flag",                         test_quiet_flag },
		{ "insecure/flag",                      test_insecure_flag },
		{ "output_format/space",                test_output_format_space },
		{ "output_format/equals",               test_output_format_equals },
		{ "output_format/missing_value",        test_output_format_missing_value },
		{ "output_tcp/space",                   test_output_tcp_space },
		{ "output_tcp/equals",                  test_output_tcp_equals },
		{ "output_tcp/missing_value",           test_output_tcp_missing_value },
		{ "output_http/http_url",               test_output_http_http_url },
		{ "output_http/https_url",              test_output_http_https_url },
		{ "output_http/equals_form",            test_output_http_equals_form },
		{ "output_http/missing_value",          test_output_http_missing_value },
		{ "script/space",                       test_script_space },
		{ "script/equals",                      test_script_equals },
		{ "script/missing_value",               test_script_missing_value },
		{ "remote/space",                       test_remote_space },
		{ "remote/equals",                      test_remote_equals },
		{ "remote/missing_value",               test_remote_missing_value },
		{ "retry/space_valid",                  test_retry_space_valid },
		{ "retry/equals_valid",                 test_retry_equals_valid },
		{ "retry/zero_valid",                   test_retry_zero_valid },
		{ "retry/boundary_1000",                test_retry_boundary_1000 },
		{ "retry/over_limit",                   test_retry_over_limit },
		{ "retry/negative",                     test_retry_negative },
		{ "retry/non_numeric",                  test_retry_non_numeric },
		{ "retry/missing_value",                test_retry_missing_value },
		{ "api_key/space",                      test_api_key_space },
		{ "api_key/equals",                     test_api_key_equals },
		{ "api_key/missing_value",              test_api_key_missing_value },
		{ "cmd_idx/subcommand",                 test_cmd_idx_subcommand },
		{ "cmd_idx/after_flags",                test_cmd_idx_after_flags },
		{ "env/output_format_default",          test_env_output_format_default },
		{ "env/output_format_cli_overrides",    test_env_output_format_cli_overrides },
		{ "env/quiet_1",                        test_env_quiet },
		{ "env/quiet_true",                     test_env_quiet_true },
		{ "env/quiet_yes",                      test_env_quiet_yes },
		{ "env/quiet_on",                       test_env_quiet_on },
		{ "env/quiet_other_verbose",            test_env_quiet_other_value_verbose },
		{ "env/insecure",                       test_env_insecure },
		{ "env/ws_retry",                       test_env_ws_retry },
		{ "env/ws_retry_invalid_keeps_default", test_env_ws_retry_invalid_keeps_default },
		{ "env/output_tcp",                     test_env_output_tcp },
		{ "env/api_url_fallback_http",          test_env_api_url_fallback_http },
		{ "env/api_url_fallback_https",         test_env_api_url_fallback_https },
		{ "env/api_url_not_applied_when_set",   test_env_api_url_not_applied_when_http_already_set },
		{ "env/api_insecure",                   test_env_api_insecure },
		{ "env/script_fallback",                test_env_script_fallback },
		{ "env/script_not_applied_with_cmd",    test_env_script_not_applied_when_cmd_present },
		{ "combined/flags",                     test_combined_flags },
		{ "null_errbuf_no_crash",               test_null_errbuf_no_crash },
	};
	return ela_run_test_suite("dispatch_parse_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
