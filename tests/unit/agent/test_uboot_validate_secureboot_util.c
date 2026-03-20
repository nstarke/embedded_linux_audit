// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/audit-rules/uboot_validate_secureboot_util.h"

#include <string.h>

/* =========================================================================
 * ela_uboot_secureboot_check_env_policy
 * ====================================================================== */

static void test_all_valid_zero_issues(void)
{
	char detail[256] = "";

	ELA_ASSERT_INT_EQ(0, ela_uboot_secureboot_check_env_policy(
		"enabled", "yes", "enabled", "abc123sig", detail, sizeof(detail)));
	ELA_ASSERT_INT_EQ(0, detail[0]);
}

static void test_secureboot_missing(void)
{
	char detail[256] = "";

	ELA_ASSERT_INT_EQ(1, ela_uboot_secureboot_check_env_policy(
		NULL, "yes", "enabled", "abc123sig", detail, sizeof(detail)));
	ELA_ASSERT_TRUE(strstr(detail, "secureboot") != NULL);
}

static void test_secureboot_disabled(void)
{
	char detail[256] = "";

	ELA_ASSERT_INT_EQ(1, ela_uboot_secureboot_check_env_policy(
		"disabled", "yes", "enabled", "abc123sig", detail, sizeof(detail)));
	ELA_ASSERT_TRUE(strstr(detail, "secureboot=disabled") != NULL);
}

static void test_verify_missing(void)
{
	char detail[256] = "";

	ELA_ASSERT_INT_EQ(1, ela_uboot_secureboot_check_env_policy(
		"enabled", NULL, "enabled", "abc123sig", detail, sizeof(detail)));
	ELA_ASSERT_TRUE(strstr(detail, "verify") != NULL);
}

static void test_verify_disabled(void)
{
	char detail[256] = "";

	ELA_ASSERT_INT_EQ(1, ela_uboot_secureboot_check_env_policy(
		"enabled", "disabled", "enabled", "abc123sig", detail, sizeof(detail)));
	ELA_ASSERT_TRUE(strstr(detail, "verify=disabled") != NULL);
}

static void test_bootm_verify_sig_missing(void)
{
	char detail[256] = "";

	ELA_ASSERT_INT_EQ(1, ela_uboot_secureboot_check_env_policy(
		"enabled", "yes", NULL, "abc123sig", detail, sizeof(detail)));
	ELA_ASSERT_TRUE(strstr(detail, "bootm_verify_sig") != NULL);
}

static void test_bootm_verify_sig_disabled(void)
{
	char detail[256] = "";

	ELA_ASSERT_INT_EQ(1, ela_uboot_secureboot_check_env_policy(
		"enabled", "yes", "disabled", "abc123sig", detail, sizeof(detail)));
}

static void test_signature_missing(void)
{
	char detail[256] = "";

	ELA_ASSERT_INT_EQ(1, ela_uboot_secureboot_check_env_policy(
		"enabled", "yes", "enabled", NULL, detail, sizeof(detail)));
	ELA_ASSERT_TRUE(strstr(detail, "signature") != NULL);
}

static void test_signature_empty(void)
{
	char detail[256] = "";

	ELA_ASSERT_INT_EQ(1, ela_uboot_secureboot_check_env_policy(
		"enabled", "yes", "enabled", "", detail, sizeof(detail)));
}

static void test_all_four_missing(void)
{
	char detail[256] = "";

	ELA_ASSERT_INT_EQ(4, ela_uboot_secureboot_check_env_policy(
		NULL, NULL, NULL, NULL, detail, sizeof(detail)));
}

static void test_two_issues_detail_joined(void)
{
	char detail[256] = "";
	int issues;

	issues = ela_uboot_secureboot_check_env_policy(
		NULL, "disabled", "enabled", "sig123", detail, sizeof(detail));
	ELA_ASSERT_INT_EQ(2, issues);
	ELA_ASSERT_TRUE(strstr(detail, "secureboot") != NULL);
	ELA_ASSERT_TRUE(strstr(detail, "verify") != NULL);
}

static void test_secureboot_verify_nonenabled(void)
{
	/* verify="no" — value_is_disabled("no") is false, but value_is_enabled("no") is
	 * also false for secureboot check. This tests the verify path: !verify ||
	 * value_is_disabled(verify) — "no" is not disabled so verify passes. */
	char detail[256] = "";

	/* "no" is not "disabled"/"0"/"false" — depends on ela_uboot_value_is_disabled impl.
	 * We test with "0" which is a known disabled value. */
	ELA_ASSERT_INT_EQ(1, ela_uboot_secureboot_check_env_policy(
		"enabled", "0", "enabled", "abc123sig", detail, sizeof(detail)));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_validate_secureboot_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "all_valid_zero_issues",         test_all_valid_zero_issues },
		{ "secureboot_missing",            test_secureboot_missing },
		{ "secureboot_disabled",           test_secureboot_disabled },
		{ "verify_missing",                test_verify_missing },
		{ "verify_disabled",               test_verify_disabled },
		{ "bootm_verify_sig_missing",      test_bootm_verify_sig_missing },
		{ "bootm_verify_sig_disabled",     test_bootm_verify_sig_disabled },
		{ "signature_missing",             test_signature_missing },
		{ "signature_empty",               test_signature_empty },
		{ "all_four_missing",              test_all_four_missing },
		{ "two_issues_detail_joined",      test_two_issues_detail_joined },
		{ "verify_zero_is_disabled",       test_secureboot_verify_nonenabled },
	};
	return ela_run_test_suite("uboot_validate_secureboot_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
