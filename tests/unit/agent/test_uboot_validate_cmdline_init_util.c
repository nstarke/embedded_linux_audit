// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/audit-rules/uboot_validate_cmdline_init_util.h"

#include <string.h>

/* =========================================================================
 * ela_uboot_cmdline_init_writeability_result
 * ====================================================================== */

static void test_no_init_returns_zero(void)
{
	char msg[256];

	ELA_ASSERT_INT_EQ(0, ela_uboot_cmdline_init_writeability_result(
		false, false, false, "", "/dev/mtd0", msg, sizeof(msg)));
}

static void test_no_init_message(void)
{
	char msg[256];

	ela_uboot_cmdline_init_writeability_result(
		false, false, false, "", "/dev/mtd0", msg, sizeof(msg));
	ELA_ASSERT_TRUE(strstr(msg, "init= not present") != NULL);
}

static void test_init_invalid_returns_zero(void)
{
	char msg[256];

	ELA_ASSERT_INT_EQ(0, ela_uboot_cmdline_init_writeability_result(
		true, false, false, "/bad path", "/dev/mtd0", msg, sizeof(msg)));
}

static void test_init_invalid_message(void)
{
	char msg[256];

	ela_uboot_cmdline_init_writeability_result(
		true, false, false, "/bad path", "/dev/mtd0", msg, sizeof(msg));
	ELA_ASSERT_TRUE(strstr(msg, "invalid") != NULL);
	ELA_ASSERT_TRUE(strstr(msg, "/bad path") != NULL);
}

static void test_valid_not_writeable_returns_zero(void)
{
	char msg[256];

	ELA_ASSERT_INT_EQ(0, ela_uboot_cmdline_init_writeability_result(
		true, true, false, "/sbin/init", "/dev/mtd0", msg, sizeof(msg)));
}

static void test_valid_not_writeable_message(void)
{
	char msg[256];

	ela_uboot_cmdline_init_writeability_result(
		true, true, false, "/sbin/init", "/dev/mtd0", msg, sizeof(msg));
	ELA_ASSERT_TRUE(strstr(msg, "not writeable") != NULL);
	ELA_ASSERT_TRUE(strstr(msg, "/sbin/init") != NULL);
}

static void test_valid_writeable_returns_one(void)
{
	char msg[256];

	ELA_ASSERT_INT_EQ(1, ela_uboot_cmdline_init_writeability_result(
		true, true, true, "/sbin/init", "/dev/mtd0", msg, sizeof(msg)));
}

static void test_valid_writeable_message(void)
{
	char msg[256];

	ela_uboot_cmdline_init_writeability_result(
		true, true, true, "/sbin/init", "/dev/mtd0", msg, sizeof(msg));
	ELA_ASSERT_TRUE(strstr(msg, "WARNING") != NULL);
	ELA_ASSERT_TRUE(strstr(msg, "/sbin/init") != NULL);
	ELA_ASSERT_TRUE(strstr(msg, "/dev/mtd0") != NULL);
}

static void test_writeable_null_device_uses_unknown(void)
{
	char msg[256];

	ela_uboot_cmdline_init_writeability_result(
		true, true, true, "/sbin/init", NULL, msg, sizeof(msg));
	ELA_ASSERT_TRUE(strstr(msg, "(unknown)") != NULL);
}

static void test_null_message_ok(void)
{
	ELA_ASSERT_INT_EQ(0, ela_uboot_cmdline_init_writeability_result(
		false, false, false, "", "/dev/mtd0", NULL, 0));
}

static void test_null_message_writeable_ok(void)
{
	ELA_ASSERT_INT_EQ(1, ela_uboot_cmdline_init_writeability_result(
		true, true, true, "/sbin/init", "/dev/mtd0", NULL, 0));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_validate_cmdline_init_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "no_init_returns_zero",          test_no_init_returns_zero },
		{ "no_init_message",               test_no_init_message },
		{ "init_invalid_returns_zero",     test_init_invalid_returns_zero },
		{ "init_invalid_message",          test_init_invalid_message },
		{ "valid_not_writeable_zero",      test_valid_not_writeable_returns_zero },
		{ "valid_not_writeable_message",   test_valid_not_writeable_message },
		{ "valid_writeable_one",           test_valid_writeable_returns_one },
		{ "valid_writeable_message",       test_valid_writeable_message },
		{ "null_device_unknown",           test_writeable_null_device_uses_unknown },
		{ "null_message_ok",               test_null_message_ok },
		{ "null_message_writeable_ok",     test_null_message_writeable_ok },
	};
	return ela_run_test_suite("uboot_validate_cmdline_init_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
