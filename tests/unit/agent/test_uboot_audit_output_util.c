// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/audit/uboot_audit_output_util.h"

#include <string.h>

/* =========================================================================
 * ela_uboot_audit_http_content_type
 * ====================================================================== */

static void test_content_type_json(void)
{
	ELA_ASSERT_STR_EQ("application/x-ndjson; charset=utf-8",
			  ela_uboot_audit_http_content_type(FW_OUTPUT_JSON));
}

static void test_content_type_csv(void)
{
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8",
			  ela_uboot_audit_http_content_type(FW_OUTPUT_CSV));
}

static void test_content_type_txt(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_uboot_audit_http_content_type(FW_OUTPUT_TXT));
}

static void test_content_type_unknown_defaults_to_plain(void)
{
	/* any value not explicitly handled falls through to text/plain */
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_uboot_audit_http_content_type((enum uboot_output_format)99));
}

/* =========================================================================
 * ela_uboot_audit_rule_name_selected
 * ====================================================================== */

static void test_selected_null_rule(void)
{
	ELA_ASSERT_FALSE(ela_uboot_audit_rule_name_selected(NULL, NULL));
}

static void test_selected_rule_null_name(void)
{
	struct embedded_linux_audit_rule rule = { NULL, NULL, NULL };
	ELA_ASSERT_FALSE(ela_uboot_audit_rule_name_selected(NULL, &rule));
}

static void test_selected_rule_empty_name(void)
{
	struct embedded_linux_audit_rule rule = { "", NULL, NULL };
	ELA_ASSERT_FALSE(ela_uboot_audit_rule_name_selected(NULL, &rule));
}

static void test_selected_null_filter_selects_all(void)
{
	struct embedded_linux_audit_rule rule = { "myrule", NULL, NULL };
	ELA_ASSERT_TRUE(ela_uboot_audit_rule_name_selected(NULL, &rule));
}

static void test_selected_empty_filter_selects_all(void)
{
	struct embedded_linux_audit_rule rule = { "myrule", NULL, NULL };
	ELA_ASSERT_TRUE(ela_uboot_audit_rule_name_selected("", &rule));
}

static void test_selected_filter_matches(void)
{
	struct embedded_linux_audit_rule rule = { "uboot_validate_crc32", NULL, NULL };
	ELA_ASSERT_TRUE(ela_uboot_audit_rule_name_selected("uboot_validate_crc32", &rule));
}

static void test_selected_filter_no_match(void)
{
	struct embedded_linux_audit_rule rule = { "uboot_validate_crc32", NULL, NULL };
	ELA_ASSERT_FALSE(ela_uboot_audit_rule_name_selected("uboot_validate_secureboot", &rule));
}

static void test_selected_filter_case_sensitive(void)
{
	/* strcmp is used, not strcasecmp */
	struct embedded_linux_audit_rule rule = { "myrule", NULL, NULL };
	ELA_ASSERT_FALSE(ela_uboot_audit_rule_name_selected("MYRULE", &rule));
}

/* =========================================================================
 * ela_uboot_audit_rc_to_status
 * ====================================================================== */

static void test_status_zero_is_pass(void)
{
	ELA_ASSERT_STR_EQ("pass", ela_uboot_audit_rc_to_status(0));
}

static void test_status_one_is_fail(void)
{
	ELA_ASSERT_STR_EQ("fail", ela_uboot_audit_rc_to_status(1));
}

static void test_status_large_positive_is_fail(void)
{
	ELA_ASSERT_STR_EQ("fail", ela_uboot_audit_rc_to_status(100));
}

static void test_status_minus_one_is_error(void)
{
	ELA_ASSERT_STR_EQ("error", ela_uboot_audit_rc_to_status(-1));
}

static void test_status_large_negative_is_error(void)
{
	ELA_ASSERT_STR_EQ("error", ela_uboot_audit_rc_to_status(-100));
}

/* =========================================================================
 * ela_uboot_audit_format_artifact
 * ====================================================================== */

static void test_artifact_null_name(void)
{
	char buf[256];
	ELA_ASSERT_INT_EQ(-1, ela_uboot_audit_format_artifact(
		FW_OUTPUT_TXT, NULL, "val", buf, sizeof(buf)));
}

static void test_artifact_null_value(void)
{
	char buf[256];
	ELA_ASSERT_INT_EQ(-1, ela_uboot_audit_format_artifact(
		FW_OUTPUT_TXT, "name", NULL, buf, sizeof(buf)));
}

static void test_artifact_null_buf(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_audit_format_artifact(
		FW_OUTPUT_TXT, "name", "val", NULL, 64));
}

static void test_artifact_zero_buflen(void)
{
	char buf[256];
	ELA_ASSERT_INT_EQ(-1, ela_uboot_audit_format_artifact(
		FW_OUTPUT_TXT, "name", "val", buf, 0));
}

static void test_artifact_txt_format(void)
{
	char buf[256];
	ELA_ASSERT_INT_EQ(0, ela_uboot_audit_format_artifact(
		FW_OUTPUT_TXT, "pubkey", "abc123", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("audit artifact pubkey=abc123\n", buf);
}

static void test_artifact_csv_format(void)
{
	char buf[256];
	ELA_ASSERT_INT_EQ(0, ela_uboot_audit_format_artifact(
		FW_OUTPUT_CSV, "pubkey", "abc123", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("audit_artifact,pubkey,abc123\n", buf);
}

static void test_artifact_json_format(void)
{
	char buf[256];
	ELA_ASSERT_INT_EQ(0, ela_uboot_audit_format_artifact(
		FW_OUTPUT_JSON, "pubkey", "abc123", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("{\"record\":\"audit_artifact\",\"artifact\":\"pubkey\",\"value\":\"abc123\"}\n",
			  buf);
}

static void test_artifact_unknown_format_defaults_to_txt(void)
{
	char buf[256];
	ELA_ASSERT_INT_EQ(0, ela_uboot_audit_format_artifact(
		(enum uboot_output_format)99, "k", "v", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("audit artifact k=v\n", buf);
}

static void test_artifact_truncated(void)
{
	char buf[8]; /* too small for any real payload */
	ELA_ASSERT_INT_EQ(1, ela_uboot_audit_format_artifact(
		FW_OUTPUT_TXT, "pubkey", "abc123", buf, sizeof(buf)));
}

static void test_artifact_exact_fit_txt(void)
{
	/* "audit artifact k=v\n" = 19 chars + NUL = 20 bytes */
	char buf[20];
	ELA_ASSERT_INT_EQ(0, ela_uboot_audit_format_artifact(
		FW_OUTPUT_TXT, "k", "v", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("audit artifact k=v\n", buf);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_audit_output_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* http_content_type */
		{ "content_type/json",              test_content_type_json },
		{ "content_type/csv",               test_content_type_csv },
		{ "content_type/txt",               test_content_type_txt },
		{ "content_type/unknown_default",   test_content_type_unknown_defaults_to_plain },
		/* rule_name_selected */
		{ "selected/null_rule",             test_selected_null_rule },
		{ "selected/rule_null_name",        test_selected_rule_null_name },
		{ "selected/rule_empty_name",       test_selected_rule_empty_name },
		{ "selected/null_filter_all",       test_selected_null_filter_selects_all },
		{ "selected/empty_filter_all",      test_selected_empty_filter_selects_all },
		{ "selected/filter_matches",        test_selected_filter_matches },
		{ "selected/filter_no_match",       test_selected_filter_no_match },
		{ "selected/case_sensitive",        test_selected_filter_case_sensitive },
		/* rc_to_status */
		{ "status/zero_pass",               test_status_zero_is_pass },
		{ "status/one_fail",                test_status_one_is_fail },
		{ "status/positive_fail",           test_status_large_positive_is_fail },
		{ "status/minus_one_error",         test_status_minus_one_is_error },
		{ "status/negative_error",          test_status_large_negative_is_error },
		/* format_artifact */
		{ "artifact/null_name",             test_artifact_null_name },
		{ "artifact/null_value",            test_artifact_null_value },
		{ "artifact/null_buf",              test_artifact_null_buf },
		{ "artifact/zero_buflen",           test_artifact_zero_buflen },
		{ "artifact/txt",                   test_artifact_txt_format },
		{ "artifact/csv",                   test_artifact_csv_format },
		{ "artifact/json",                  test_artifact_json_format },
		{ "artifact/unknown_fmt_txt",       test_artifact_unknown_format_defaults_to_txt },
		{ "artifact/truncated",             test_artifact_truncated },
		{ "artifact/exact_fit",             test_artifact_exact_fit_txt },
	};
	return ela_run_test_suite("uboot_audit_output_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
