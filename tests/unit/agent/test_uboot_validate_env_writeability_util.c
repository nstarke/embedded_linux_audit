// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/audit-rules/uboot_validate_env_writeability_util.h"

#include <errno.h>

/* =========================================================================
 * ela_uboot_validate_env_errno_classify
 * ====================================================================== */

static void test_eacces_is_pass(void)
{
	ELA_ASSERT_INT_EQ(0, ela_uboot_validate_env_errno_classify(EACCES));
}

static void test_eperm_is_pass(void)
{
	ELA_ASSERT_INT_EQ(0, ela_uboot_validate_env_errno_classify(EPERM));
}

static void test_erofs_is_pass(void)
{
	ELA_ASSERT_INT_EQ(0, ela_uboot_validate_env_errno_classify(EROFS));
}

static void test_enoent_is_error(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_validate_env_errno_classify(ENOENT));
}

static void test_ebusy_is_error(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_validate_env_errno_classify(EBUSY));
}

static void test_eio_is_error(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_validate_env_errno_classify(EIO));
}

static void test_zero_is_error(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_validate_env_errno_classify(0));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_validate_env_writeability_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "eacces_is_pass",  test_eacces_is_pass },
		{ "eperm_is_pass",   test_eperm_is_pass },
		{ "erofs_is_pass",   test_erofs_is_pass },
		{ "enoent_is_error", test_enoent_is_error },
		{ "ebusy_is_error",  test_ebusy_is_error },
		{ "eio_is_error",    test_eio_is_error },
		{ "zero_is_error",   test_zero_is_error },
	};
	return ela_run_test_suite("uboot_validate_env_writeability_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
