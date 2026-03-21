// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/shell/interactive_util.h"

#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * ela_interactive_candidates_for_position
 * ---------------------------------------------------------------------- */

static void test_candidates_argc_zero_or_one(void)
{
	char *argv_linux[] = { "linux" };
	const char *const *candidates;

	/* argc <= 1 always returns top-level commands */
	candidates = ela_interactive_candidates_for_position(0, NULL);
	ELA_ASSERT_TRUE(candidates != NULL);
	ELA_ASSERT_STR_EQ("help", candidates[0]);

	candidates = ela_interactive_candidates_for_position(1, argv_linux);
	ELA_ASSERT_TRUE(candidates != NULL);
	ELA_ASSERT_STR_EQ("help", candidates[0]);
}

static void test_candidates_group_uboot(void)
{
	char *argv[] = { "uboot" };
	const char *const *candidates = ela_interactive_candidates_for_position(2, argv);

	ELA_ASSERT_TRUE(candidates != NULL);
	ELA_ASSERT_STR_EQ("env", candidates[0]);
	ELA_ASSERT_STR_EQ("image", candidates[1]);
	ELA_ASSERT_STR_EQ("audit", candidates[2]);
}

static void test_candidates_group_linux(void)
{
	char *argv[] = { "linux" };
	const char *const *candidates = ela_interactive_candidates_for_position(2, argv);

	ELA_ASSERT_TRUE(candidates != NULL);
	ELA_ASSERT_STR_EQ("dmesg", candidates[0]);
}

static void test_candidates_linux_includes_process_and_gdbserver(void)
{
	char *argv[] = { "linux" };
	const char *const *candidates = ela_interactive_candidates_for_position(2, argv);
	int found_process = 0, found_gdbserver = 0;
	int i;

	ELA_ASSERT_TRUE(candidates != NULL);
	for (i = 0; candidates[i] != NULL; i++) {
		if (!strcmp(candidates[i], "process"))
			found_process = 1;
		if (!strcmp(candidates[i], "gdbserver"))
			found_gdbserver = 1;
	}
	ELA_ASSERT_TRUE(found_process);
	ELA_ASSERT_TRUE(found_gdbserver);
}

static void test_candidates_linux_process_subcommand(void)
{
	char *argv[] = { "linux", "process" };
	const char *const *candidates = ela_interactive_candidates_for_position(3, argv);

	ELA_ASSERT_TRUE(candidates != NULL);
	ELA_ASSERT_STR_EQ("watch", candidates[0]);
	ELA_ASSERT_TRUE(candidates[1] == NULL);
}

static void test_candidates_linux_process_watch_subcommand(void)
{
	char *argv[] = { "linux", "process", "watch" };
	const char *const *candidates = ela_interactive_candidates_for_position(4, argv);

	ELA_ASSERT_TRUE(candidates != NULL);
	ELA_ASSERT_STR_EQ("on", candidates[0]);
	ELA_ASSERT_STR_EQ("off", candidates[1]);
	ELA_ASSERT_STR_EQ("list", candidates[2]);
	ELA_ASSERT_TRUE(candidates[3] == NULL);
}

static void test_candidates_linux_process_watch_arg_returns_null(void)
{
	char *argv[] = { "linux", "process", "watch", "on" };
	const char *const *candidates = ela_interactive_candidates_for_position(5, argv);

	ELA_ASSERT_TRUE(candidates == NULL);
}

static void test_candidates_linux_gdbserver_returns_linux_list(void)
{
	/* gdbserver takes positional args, not subcommands — no completions beyond linux */
	char *argv[] = { "linux", "gdbserver" };
	const char *const *candidates = ela_interactive_candidates_for_position(3, argv);

	ELA_ASSERT_TRUE(candidates == NULL);
}

static void test_candidates_group_arch(void)
{
	char *argv[] = { "arch" };
	const char *const *candidates = ela_interactive_candidates_for_position(2, argv);

	ELA_ASSERT_TRUE(candidates != NULL);
	ELA_ASSERT_STR_EQ("bit", candidates[0]);
}

static void test_candidates_group_efi(void)
{
	char *argv[] = { "efi" };
	const char *const *candidates = ela_interactive_candidates_for_position(2, argv);

	ELA_ASSERT_TRUE(candidates != NULL);
	ELA_ASSERT_STR_EQ("orom", candidates[0]);
	ELA_ASSERT_STR_EQ("dump-vars", candidates[1]);
}

static void test_candidates_group_bios(void)
{
	char *argv[] = { "bios" };
	const char *const *candidates = ela_interactive_candidates_for_position(2, argv);

	ELA_ASSERT_TRUE(candidates != NULL);
	ELA_ASSERT_STR_EQ("orom", candidates[0]);
	ELA_ASSERT_TRUE(candidates[1] == NULL);
}

static void test_candidates_set_variables(void)
{
	char *argv[] = { "set", "ELA_" };
	const char *const *candidates;

	/* argc == 2 + argv[0]=="set" */
	candidates = ela_interactive_candidates_for_position(2, argv);
	ELA_ASSERT_TRUE(candidates != NULL);
	ELA_ASSERT_STR_EQ("ELA_API_URL", candidates[0]);
}

static void test_candidates_set_argc_three_returns_null(void)
{
	char *argv[] = { "set", "ELA_API_URL" };
	/* argc == 3: already have variable name, no further completions */
	const char *const *candidates = ela_interactive_candidates_for_position(3, argv);

	ELA_ASSERT_TRUE(candidates == NULL);
}

static void test_candidates_unknown_group_returns_null(void)
{
	char *argv[] = { "frobnicate" };
	const char *const *candidates = ela_interactive_candidates_for_position(2, argv);

	ELA_ASSERT_TRUE(candidates == NULL);
}

/* -------------------------------------------------------------------------
 * ela_interactive_format_supported_variables
 * ---------------------------------------------------------------------- */

static void test_format_supported_vars_null_buf(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_interactive_format_supported_variables(
		NULL, 128, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_format_supported_vars_zero_buf_sz(void)
{
	char buf[128];

	ELA_ASSERT_INT_EQ(-1, ela_interactive_format_supported_variables(
		buf, 0, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_format_supported_vars_buf_too_small(void)
{
	char buf[4];

	ELA_ASSERT_INT_EQ(-1, ela_interactive_format_supported_variables(
		buf, sizeof(buf), "http://example.com", NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_format_supported_vars_all_null(void)
{
	char buf[2048];
	int rc = ela_interactive_format_supported_variables(
		buf, sizeof(buf), NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_TRUE(strstr(buf, "ELA_API_URL              current=<unset>") != NULL);
	ELA_ASSERT_TRUE(strstr(buf, "ELA_API_KEY              current=<unset>") != NULL);
	ELA_ASSERT_TRUE(strstr(buf, "ELA_VERBOSE              current=<unset>") != NULL);
	ELA_ASSERT_TRUE(strstr(buf, "ELA_WS_RETRY_ATTEMPTS    current=<unset>") != NULL);
}

static void test_format_supported_vars_empty_string_is_unset(void)
{
	char buf[2048];

	ELA_ASSERT_INT_EQ(0, ela_interactive_format_supported_variables(
		buf, sizeof(buf), "", NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL));
	ELA_ASSERT_TRUE(strstr(buf, "ELA_API_URL              current=<unset>") != NULL);
}

static void test_format_supported_vars_api_key_masked(void)
{
	char buf[2048];

	/* api_key is non-null and non-empty → shown as "<set>" */
	ELA_ASSERT_INT_EQ(0, ela_interactive_format_supported_variables(
		buf, sizeof(buf), NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, "mysecret", NULL, NULL, NULL));
	ELA_ASSERT_TRUE(strstr(buf, "ELA_API_KEY              current=<set>") != NULL);
}

static void test_format_supported_vars_normal(void)
{
	char buf[2048];

	ELA_ASSERT_INT_EQ(0, ela_interactive_format_supported_variables(
		buf, sizeof(buf),
		"https://ela.example", "true", NULL, "json",
		"127.0.0.1:9000", "./script.ela", NULL, "false",
		"secret", "true", NULL, "5"));
	ELA_ASSERT_TRUE(strstr(buf, "ELA_API_URL              current=https://ela.example") != NULL);
	ELA_ASSERT_TRUE(strstr(buf, "ELA_API_KEY              current=<set>") != NULL);
	ELA_ASSERT_TRUE(strstr(buf, "ELA_DEBUG                current=<unset>") != NULL);
	ELA_ASSERT_TRUE(strstr(buf, "ELA_WS_RETRY_ATTEMPTS    current=5") != NULL);
}

/* -------------------------------------------------------------------------
 * ela_interactive_plan_set_command
 * ---------------------------------------------------------------------- */

static void test_plan_set_null_args(void)
{
	struct ela_interactive_set_plan plan;
	char errbuf[128];

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(NULL, "v", &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command("n", NULL, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command("n", "v", NULL, errbuf, sizeof(errbuf)));
}

static void test_plan_set_api_url_http(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_API_URL", "http://127.0.0.1:5000/api", &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_API_URL, plan.kind);
	ELA_ASSERT_STR_EQ("ELA_API_URL", plan.display_name);
	ELA_ASSERT_STR_EQ("ELA_API_URL", plan.primary_env_name);
	ELA_ASSERT_TRUE(plan.clear_output_overrides);
	ELA_ASSERT_TRUE(plan.update_conf);
}

static void test_plan_set_api_url_https(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_API_URL", "https://host:8443/api", &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_API_URL, plan.kind);
}

static void test_plan_set_api_url_invalid_scheme(void)
{
	struct ela_interactive_set_plan plan;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(
		"ELA_API_URL", "ftp://bad/path", &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid ELA_API_URL") != NULL);
}

static void test_plan_set_api_insecure_valid(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_API_INSECURE", "true", &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_API_INSECURE, plan.kind);
	ELA_ASSERT_TRUE(plan.update_conf);

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_API_INSECURE", "false", &plan, NULL, 0));
}

static void test_plan_set_api_insecure_invalid(void)
{
	struct ela_interactive_set_plan plan;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(
		"ELA_API_INSECURE", "maybe", &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid") != NULL);
}

static void test_plan_set_quiet(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command("ELA_QUIET", "true", &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_QUIET, plan.kind);

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command("ELA_QUIET", "maybe", &plan, NULL, 0));
}

static void test_plan_set_output_format_valid(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command("ELA_OUTPUT_FORMAT", "txt",  &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_OUTPUT_FORMAT, plan.kind);
	ELA_ASSERT_TRUE(plan.update_conf);

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command("ELA_OUTPUT_FORMAT", "csv",  &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command("ELA_OUTPUT_FORMAT", "json", &plan, NULL, 0));
}

static void test_plan_set_output_format_invalid(void)
{
	struct ela_interactive_set_plan plan;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(
		"ELA_OUTPUT_FORMAT", "yaml", &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid ELA_OUTPUT_FORMAT") != NULL);
}

static void test_plan_set_output_tcp_valid(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_OUTPUT_TCP", "1.2.3.4:9000", &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_OUTPUT_TCP, plan.kind);
	ELA_ASSERT_STR_EQ("ELA_OUTPUT_TCP", plan.primary_env_name);
}

static void test_plan_set_output_tcp_invalid(void)
{
	struct ela_interactive_set_plan plan;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(
		"ELA_OUTPUT_TCP", "not-an-ip:port", &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid ELA_OUTPUT_TCP") != NULL);
}

static void test_plan_set_script(void)
{
	struct ela_interactive_set_plan plan;

	/* ELA_SCRIPT accepts any value without validation */
	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_SCRIPT", "./my-script.ela", &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_SCRIPT, plan.kind);
	ELA_ASSERT_STR_EQ("./my-script.ela", plan.primary_env_value);
}

static void test_plan_set_output_http_http_scheme(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_OUTPUT_HTTP", "http://host:8080/upload", &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_OUTPUT_HTTP, plan.kind);
	ELA_ASSERT_STR_EQ("ELA_OUTPUT_HTTP",  plan.primary_env_name);
	ELA_ASSERT_STR_EQ("ELA_OUTPUT_HTTPS", plan.unset_env_name);
	ELA_ASSERT_TRUE(plan.update_conf);
}

static void test_plan_set_output_http_https_scheme(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_OUTPUT_HTTP", "https://host:8443/upload", &plan, NULL, 0));
	ELA_ASSERT_STR_EQ("ELA_OUTPUT_HTTPS", plan.primary_env_name);
	ELA_ASSERT_STR_EQ("ELA_OUTPUT_HTTP",  plan.unset_env_name);
}

static void test_plan_set_output_http_invalid_scheme(void)
{
	struct ela_interactive_set_plan plan;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(
		"ELA_OUTPUT_HTTP", "ftp://host/path", &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid ELA_OUTPUT_HTTP") != NULL);
}

static void test_plan_set_output_insecure(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_OUTPUT_INSECURE", "true", &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_OUTPUT_INSECURE, plan.kind);
	ELA_ASSERT_TRUE(plan.update_conf);

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(
		"ELA_OUTPUT_INSECURE", "bad", &plan, NULL, 0));
}

static void test_plan_set_api_key_normal(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_API_KEY", "mytoken", &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_API_KEY, plan.kind);
	ELA_ASSERT_TRUE(plan.redact_value);
	ELA_ASSERT_STR_EQ("mytoken", plan.primary_env_value);
}

static void test_plan_set_api_key_too_long(void)
{
	struct ela_interactive_set_plan plan;
	char errbuf[128] = { 0 };
	char big[1026];

	memset(big, 'x', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(
		"ELA_API_KEY", big, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "ELA_API_KEY") != NULL);
}

static void test_plan_set_verbose(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command("ELA_VERBOSE", "true",  &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_VERBOSE, plan.kind);

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command("ELA_VERBOSE", "false", &plan, NULL, 0));

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command("ELA_VERBOSE", "bad",   &plan, NULL, 0));
}

static void test_plan_set_debug(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command("ELA_DEBUG", "false", &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_DEBUG, plan.kind);
}

static void test_plan_set_ws_retry_valid(void)
{
	struct ela_interactive_set_plan plan;

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_WS_RETRY_ATTEMPTS", "0", &plan, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_INTERACTIVE_SET_WS_RETRY_ATTEMPTS, plan.kind);

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_WS_RETRY_ATTEMPTS", "500", &plan, NULL, 0));

	ELA_ASSERT_INT_EQ(0, ela_interactive_plan_set_command(
		"ELA_WS_RETRY_ATTEMPTS", "1000", &plan, NULL, 0));
}

static void test_plan_set_ws_retry_invalid(void)
{
	struct ela_interactive_set_plan plan;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(
		"ELA_WS_RETRY_ATTEMPTS", "1001", &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid ELA_WS_RETRY_ATTEMPTS") != NULL);

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(
		"ELA_WS_RETRY_ATTEMPTS", "-1", &plan, NULL, 0));

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(
		"ELA_WS_RETRY_ATTEMPTS", "abc", &plan, NULL, 0));
}

static void test_plan_set_unknown_variable(void)
{
	struct ela_interactive_set_plan plan;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_interactive_plan_set_command(
		"ELA_UNKNOWN_VAR", "value", &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unsupported variable") != NULL);
}

/* -------------------------------------------------------------------------
 * ela_interactive_is_exit_command / ela_interactive_is_help_command
 * ---------------------------------------------------------------------- */

static void test_is_exit_command(void)
{
	ELA_ASSERT_TRUE(ela_interactive_is_exit_command("quit"));
	ELA_ASSERT_TRUE(ela_interactive_is_exit_command("exit"));
	ELA_ASSERT_FALSE(ela_interactive_is_exit_command(NULL));
	ELA_ASSERT_FALSE(ela_interactive_is_exit_command("help"));
	ELA_ASSERT_FALSE(ela_interactive_is_exit_command("set"));
	ELA_ASSERT_FALSE(ela_interactive_is_exit_command(""));
}

static void test_is_help_command(void)
{
	ELA_ASSERT_TRUE(ela_interactive_is_help_command("help"));
	ELA_ASSERT_FALSE(ela_interactive_is_help_command(NULL));
	ELA_ASSERT_FALSE(ela_interactive_is_help_command("quit"));
	ELA_ASSERT_FALSE(ela_interactive_is_help_command("exit"));
	ELA_ASSERT_FALSE(ela_interactive_is_help_command("HELP"));
}

/* -------------------------------------------------------------------------
 * ela_interactive_should_show_prompt
 * ---------------------------------------------------------------------- */

static void test_should_show_prompt(void)
{
	/* tty_fd >= 0 → show regardless of session_mac */
	ELA_ASSERT_TRUE(ela_interactive_should_show_prompt(0,  NULL));
	ELA_ASSERT_TRUE(ela_interactive_should_show_prompt(1,  NULL));

	/* session_mac non-empty → show even without tty */
	ELA_ASSERT_TRUE(ela_interactive_should_show_prompt(-1, "aa:bb"));

	/* neither tty nor session_mac → do not show */
	ELA_ASSERT_FALSE(ela_interactive_should_show_prompt(-1, NULL));
	ELA_ASSERT_FALSE(ela_interactive_should_show_prompt(-1, ""));
}

/* -------------------------------------------------------------------------
 * ela_interactive_build_prompt
 * ---------------------------------------------------------------------- */

static void test_build_prompt_null_buf(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_interactive_build_prompt(NULL, 64, "prog", NULL, true));
}

static void test_build_prompt_zero_buf_sz(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(-1, ela_interactive_build_prompt(buf, 0, "prog", NULL, true));
}

static void test_build_prompt_show_false(void)
{
	char buf[64] = "x";

	ELA_ASSERT_INT_EQ(0, ela_interactive_build_prompt(buf, sizeof(buf), "prog", NULL, false));
	ELA_ASSERT_INT_EQ('\0', buf[0]);
}

static void test_build_prompt_with_session_mac(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(0, ela_interactive_build_prompt(buf, sizeof(buf),
							  "/usr/bin/ela", "aa:bb", true));
	ELA_ASSERT_STR_EQ("(aa:bb)> ", buf);
}

static void test_build_prompt_basename(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(0, ela_interactive_build_prompt(buf, sizeof(buf),
							  "/usr/bin/ela", NULL, true));
	ELA_ASSERT_STR_EQ("ela> ", buf);
}

static void test_build_prompt_no_slash_in_prog(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(0, ela_interactive_build_prompt(buf, sizeof(buf),
							  "ela", NULL, true));
	ELA_ASSERT_STR_EQ("ela> ", buf);
}

static void test_build_prompt_null_prog(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(0, ela_interactive_build_prompt(buf, sizeof(buf),
							  NULL, NULL, true));
	ELA_ASSERT_STR_EQ("> ", buf);
}

static void test_build_prompt_buf_too_small(void)
{
	char buf[4]; /* too small for "ela> " */

	ELA_ASSERT_INT_EQ(-1, ela_interactive_build_prompt(buf, sizeof(buf),
							   "ela", NULL, true));
}

/* -------------------------------------------------------------------------
 * ela_interactive_history_add / ela_interactive_history_free
 * ---------------------------------------------------------------------- */

static void test_history_add_null_history(void)
{
	ELA_ASSERT_INT_EQ(0, ela_interactive_history_add(NULL, "linux dmesg"));
}

static void test_history_add_null_or_empty_line(void)
{
	struct ela_interactive_history history = {0};

	ELA_ASSERT_INT_EQ(0, ela_interactive_history_add(&history, NULL));
	ELA_ASSERT_INT_EQ(0, (int)history.count);

	ELA_ASSERT_INT_EQ(0, ela_interactive_history_add(&history, ""));
	ELA_ASSERT_INT_EQ(0, (int)history.count);

	ela_interactive_history_free(&history);
}

static void test_history_add_entries(void)
{
	struct ela_interactive_history history = {0};

	ELA_ASSERT_INT_EQ(0, ela_interactive_history_add(&history, "linux dmesg"));
	ELA_ASSERT_INT_EQ(1, (int)history.count);
	ELA_ASSERT_STR_EQ("linux dmesg", history.entries[0]);

	ELA_ASSERT_INT_EQ(0, ela_interactive_history_add(&history, "uboot env"));
	ELA_ASSERT_INT_EQ(2, (int)history.count);
	ELA_ASSERT_STR_EQ("uboot env", history.entries[1]);

	ela_interactive_history_free(&history);
}

static void test_history_capacity_growth(void)
{
	struct ela_interactive_history history = {0};
	int i;

	/* Add 20 entries to force at least one realloc (initial cap is 16) */
	for (i = 0; i < 20; i++) {
		char line[32];
		snprintf(line, sizeof(line), "cmd %d", i);
		ELA_ASSERT_INT_EQ(0, ela_interactive_history_add(&history, line));
	}

	ELA_ASSERT_INT_EQ(20, (int)history.count);
	ELA_ASSERT_TRUE(history.cap >= 20);

	ela_interactive_history_free(&history);
}

static void test_history_free_null(void)
{
	ela_interactive_history_free(NULL); /* must not crash */
}

static void test_history_free_clears_state(void)
{
	struct ela_interactive_history history = {0};

	ELA_ASSERT_INT_EQ(0, ela_interactive_history_add(&history, "linux dmesg"));
	ela_interactive_history_free(&history);

	ELA_ASSERT_INT_EQ(0, (int)history.count);
	ELA_ASSERT_INT_EQ(0, (int)history.cap);
	ELA_ASSERT_TRUE(history.entries == NULL);
}

/* -------------------------------------------------------------------------
 * ela_interactive_collect_matches
 * ---------------------------------------------------------------------- */

static void test_collect_matches_null_candidates(void)
{
	const char *matches[8];

	ELA_ASSERT_INT_EQ(0, (int)ela_interactive_collect_matches(NULL, "d", matches, 8));
}

static void test_collect_matches_null_matches(void)
{
	char *argv[] = { "linux" };
	const char *const *candidates = ela_interactive_candidates_for_position(2, argv);

	ELA_ASSERT_INT_EQ(0, (int)ela_interactive_collect_matches(candidates, "d", NULL, 8));
}

static void test_collect_matches_zero_max(void)
{
	char *argv[] = { "linux" };
	const char *const *candidates = ela_interactive_candidates_for_position(2, argv);
	const char *matches[8];

	ELA_ASSERT_INT_EQ(0, (int)ela_interactive_collect_matches(candidates, "d", matches, 0));
}

static void test_collect_matches_null_prefix_returns_all(void)
{
	const char *const candidates[] = { "alpha", "beta", "gamma", NULL };
	const char *matches[8];
	size_t n = ela_interactive_collect_matches(candidates, NULL, matches, 8);

	ELA_ASSERT_INT_EQ(3, (int)n);
}

static void test_collect_matches_empty_prefix_returns_all(void)
{
	const char *const candidates[] = { "alpha", "beta", "gamma", NULL };
	const char *matches[8];
	size_t n = ela_interactive_collect_matches(candidates, "", matches, 8);

	ELA_ASSERT_INT_EQ(3, (int)n);
}

static void test_collect_matches_prefix_filters(void)
{
	char *argv[] = { "linux" };
	const char *const *candidates = ela_interactive_candidates_for_position(2, argv);
	const char *matches[8];
	size_t n = ela_interactive_collect_matches(candidates, "d", matches, 8);

	ELA_ASSERT_INT_EQ(2, (int)n);
	ELA_ASSERT_STR_EQ("dmesg",         matches[0]);
	ELA_ASSERT_STR_EQ("download-file", matches[1]);
}

static void test_collect_matches_no_match(void)
{
	const char *const candidates[] = { "alpha", "beta", NULL };
	const char *matches[8];
	size_t n = ela_interactive_collect_matches(candidates, "z", matches, 8);

	ELA_ASSERT_INT_EQ(0, (int)n);
}

static void test_collect_matches_max_cap(void)
{
	const char *const candidates[] = { "aa", "ab", "ac", "ad", NULL };
	const char *matches[2];
	size_t n = ela_interactive_collect_matches(candidates, "a", matches, 2);

	ELA_ASSERT_INT_EQ(2, (int)n);
}

int run_interactive_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* candidates */
		{ "candidates_argc_zero_or_one",          test_candidates_argc_zero_or_one },
		{ "candidates_group_uboot",                test_candidates_group_uboot },
		{ "candidates_group_linux",                test_candidates_group_linux },
		{ "candidates_linux_includes_process_and_gdbserver", test_candidates_linux_includes_process_and_gdbserver },
		{ "candidates_linux_process_subcommand",   test_candidates_linux_process_subcommand },
		{ "candidates_linux_process_watch_subcommand", test_candidates_linux_process_watch_subcommand },
		{ "candidates_linux_process_watch_arg_returns_null", test_candidates_linux_process_watch_arg_returns_null },
		{ "candidates_linux_gdbserver_returns_linux_list", test_candidates_linux_gdbserver_returns_linux_list },
		{ "candidates_group_arch",                 test_candidates_group_arch },
		{ "candidates_group_efi",                  test_candidates_group_efi },
		{ "candidates_group_bios",                 test_candidates_group_bios },
		{ "candidates_set_variables",              test_candidates_set_variables },
		{ "candidates_set_argc_three_returns_null", test_candidates_set_argc_three_returns_null },
		{ "candidates_unknown_group_returns_null", test_candidates_unknown_group_returns_null },
		/* format_supported_variables */
		{ "format_vars_null_buf",                  test_format_supported_vars_null_buf },
		{ "format_vars_zero_buf_sz",               test_format_supported_vars_zero_buf_sz },
		{ "format_vars_buf_too_small",             test_format_supported_vars_buf_too_small },
		{ "format_vars_all_null",                  test_format_supported_vars_all_null },
		{ "format_vars_empty_string_is_unset",     test_format_supported_vars_empty_string_is_unset },
		{ "format_vars_api_key_masked",            test_format_supported_vars_api_key_masked },
		{ "format_vars_normal",                    test_format_supported_vars_normal },
		/* plan_set_command */
		{ "plan_set_null_args",                    test_plan_set_null_args },
		{ "plan_set_api_url_http",                 test_plan_set_api_url_http },
		{ "plan_set_api_url_https",                test_plan_set_api_url_https },
		{ "plan_set_api_url_invalid_scheme",       test_plan_set_api_url_invalid_scheme },
		{ "plan_set_api_insecure_valid",           test_plan_set_api_insecure_valid },
		{ "plan_set_api_insecure_invalid",         test_plan_set_api_insecure_invalid },
		{ "plan_set_quiet",                        test_plan_set_quiet },
		{ "plan_set_output_format_valid",          test_plan_set_output_format_valid },
		{ "plan_set_output_format_invalid",        test_plan_set_output_format_invalid },
		{ "plan_set_output_tcp_valid",             test_plan_set_output_tcp_valid },
		{ "plan_set_output_tcp_invalid",           test_plan_set_output_tcp_invalid },
		{ "plan_set_script",                       test_plan_set_script },
		{ "plan_set_output_http_http_scheme",      test_plan_set_output_http_http_scheme },
		{ "plan_set_output_http_https_scheme",     test_plan_set_output_http_https_scheme },
		{ "plan_set_output_http_invalid_scheme",   test_plan_set_output_http_invalid_scheme },
		{ "plan_set_output_insecure",              test_plan_set_output_insecure },
		{ "plan_set_api_key_normal",               test_plan_set_api_key_normal },
		{ "plan_set_api_key_too_long",             test_plan_set_api_key_too_long },
		{ "plan_set_verbose",                      test_plan_set_verbose },
		{ "plan_set_debug",                        test_plan_set_debug },
		{ "plan_set_ws_retry_valid",               test_plan_set_ws_retry_valid },
		{ "plan_set_ws_retry_invalid",             test_plan_set_ws_retry_invalid },
		{ "plan_set_unknown_variable",             test_plan_set_unknown_variable },
		/* exit / help predicates */
		{ "is_exit_command",                       test_is_exit_command },
		{ "is_help_command",                       test_is_help_command },
		/* should_show_prompt */
		{ "should_show_prompt",                    test_should_show_prompt },
		/* build_prompt */
		{ "build_prompt_null_buf",                 test_build_prompt_null_buf },
		{ "build_prompt_zero_buf_sz",              test_build_prompt_zero_buf_sz },
		{ "build_prompt_show_false",               test_build_prompt_show_false },
		{ "build_prompt_with_session_mac",         test_build_prompt_with_session_mac },
		{ "build_prompt_basename",                 test_build_prompt_basename },
		{ "build_prompt_no_slash_in_prog",         test_build_prompt_no_slash_in_prog },
		{ "build_prompt_null_prog",                test_build_prompt_null_prog },
		{ "build_prompt_buf_too_small",            test_build_prompt_buf_too_small },
		/* history */
		{ "history_add_null_history",              test_history_add_null_history },
		{ "history_add_null_or_empty_line",        test_history_add_null_or_empty_line },
		{ "history_add_entries",                   test_history_add_entries },
		{ "history_capacity_growth",               test_history_capacity_growth },
		{ "history_free_null",                     test_history_free_null },
		{ "history_free_clears_state",             test_history_free_clears_state },
		/* collect_matches */
		{ "collect_matches_null_candidates",       test_collect_matches_null_candidates },
		{ "collect_matches_null_matches",          test_collect_matches_null_matches },
		{ "collect_matches_zero_max",              test_collect_matches_zero_max },
		{ "collect_matches_null_prefix",           test_collect_matches_null_prefix_returns_all },
		{ "collect_matches_empty_prefix",          test_collect_matches_empty_prefix_returns_all },
		{ "collect_matches_prefix_filters",        test_collect_matches_prefix_filters },
		{ "collect_matches_no_match",              test_collect_matches_no_match },
		{ "collect_matches_max_cap",               test_collect_matches_max_cap },
	};

	return ela_run_test_suite("interactive_util", cases, sizeof(cases) / sizeof(cases[0]));
}
