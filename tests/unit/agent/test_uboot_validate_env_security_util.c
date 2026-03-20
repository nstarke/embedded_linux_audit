// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/audit-rules/uboot_validate_env_security_util.h"

#include <string.h>

/* Helper: call with only the interesting vars set; all others NULL */
static int check(const char *bootdelay, const char *preboot,
		 const char *boot_targets, const char *bootcmd,
		 const char *altbootcmd, const char *bootfile,
		 const char *serverip, const char *ipaddr,
		 const char *factory_reset, const char *reset_to_defaults,
		 const char *resetenv, const char *eraseenv)
{
	char detail[512] = "";
	return ela_uboot_validate_env_security_check_vars(
		bootdelay, preboot, boot_targets, bootcmd, altbootcmd,
		bootfile, serverip, ipaddr, factory_reset, reset_to_defaults,
		resetenv, eraseenv, NULL, detail, sizeof(detail));
}

/* =========================================================================
 * Baseline — clean environment
 * ====================================================================== */

static void test_clean_env_zero_issues(void)
{
	ELA_ASSERT_INT_EQ(0, check("0", NULL, NULL, NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

/* =========================================================================
 * bootdelay checks
 * ====================================================================== */

static void test_bootdelay_missing(void)
{
	ELA_ASSERT_INT_EQ(1, check(NULL, NULL, NULL, NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_bootdelay_positive(void)
{
	ELA_ASSERT_INT_EQ(1, check("3", NULL, NULL, NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_bootdelay_invalid_string(void)
{
	ELA_ASSERT_INT_EQ(1, check("notanumber", NULL, NULL, NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_bootdelay_zero_is_ok(void)
{
	ELA_ASSERT_INT_EQ(0, check("0", NULL, NULL, NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_bootdelay_negative_is_ok(void)
{
	ELA_ASSERT_INT_EQ(0, check("-1", NULL, NULL, NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_bootdelay_i_out(void)
{
	char detail[256] = "";
	int bootdelay_i = 99;

	ela_uboot_validate_env_security_check_vars(
		"5", NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, &bootdelay_i, detail, sizeof(detail));
	ELA_ASSERT_INT_EQ(5, bootdelay_i);
}

static void test_bootdelay_i_out_null_safe(void)
{
	char detail[256] = "";

	/* Should not crash with NULL bootdelay_i_out */
	ela_uboot_validate_env_security_check_vars(
		"0", NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, detail, sizeof(detail));
}

/* =========================================================================
 * preboot checks
 * ====================================================================== */

static void test_preboot_set(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", "some_cmd", NULL, NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_preboot_network_adds_two(void)
{
	/* preboot set (1 issue) + preboot suggests network boot (1 more) = 2 */
	ELA_ASSERT_INT_EQ(2, check("0", "run dhcp", NULL, NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

/* =========================================================================
 * boot_targets checks
 * ====================================================================== */

static void test_boot_targets_usb(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, "usb mmc", NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_boot_targets_network(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, "dhcp mmc", NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_boot_targets_safe(void)
{
	ELA_ASSERT_INT_EQ(0, check("0", NULL, "mmc sata", NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

/* =========================================================================
 * bootcmd / altbootcmd network-boot checks
 * ====================================================================== */

static void test_bootcmd_network(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, NULL, "run dhcp", NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_altbootcmd_network(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, NULL, NULL, "tftpboot 0x80000000 kernel",
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

/* =========================================================================
 * Network-boot variable checks
 * ====================================================================== */

static void test_bootfile_present(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, NULL, NULL, NULL,
				   "uImage", NULL, NULL, NULL, NULL, NULL, NULL));
}

static void test_serverip_present(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, NULL, NULL, NULL,
				   NULL, "192.168.1.1", NULL, NULL, NULL, NULL, NULL));
}

static void test_ipaddr_present(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, NULL, NULL, NULL,
				   NULL, NULL, "10.0.0.5", NULL, NULL, NULL, NULL));
}

/* =========================================================================
 * Factory-reset variable checks
 * ====================================================================== */

static void test_factory_reset_var(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, NULL, NULL, NULL,
				   NULL, NULL, NULL, "yes", NULL, NULL, NULL));
}

static void test_reset_to_defaults_var(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, NULL, NULL, NULL,
				   NULL, NULL, NULL, NULL, "1", NULL, NULL));
}

static void test_resetenv_var(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, NULL, NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, "yes", NULL));
}

static void test_eraseenv_var(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, NULL, NULL, NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, "1"));
}

static void test_bootcmd_factory_reset(void)
{
	ELA_ASSERT_INT_EQ(1, check("0", NULL, NULL, "factory_reset", NULL,
				   NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

/* =========================================================================
 * Multiple issues
 * ====================================================================== */

static void test_multiple_issues(void)
{
	/* bootdelay positive + preboot set = 2 issues minimum */
	ELA_ASSERT_TRUE(check("5", "cmd", NULL, NULL, NULL,
			      NULL, NULL, NULL, NULL, NULL, NULL, NULL) >= 2);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_validate_env_security_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "clean_env",                  test_clean_env_zero_issues },
		{ "bootdelay_missing",          test_bootdelay_missing },
		{ "bootdelay_positive",         test_bootdelay_positive },
		{ "bootdelay_invalid",          test_bootdelay_invalid_string },
		{ "bootdelay_zero_ok",          test_bootdelay_zero_is_ok },
		{ "bootdelay_negative_ok",      test_bootdelay_negative_is_ok },
		{ "bootdelay_i_out",            test_bootdelay_i_out },
		{ "bootdelay_i_out_null_safe",  test_bootdelay_i_out_null_safe },
		{ "preboot_set",                test_preboot_set },
		{ "preboot_network_two",        test_preboot_network_adds_two },
		{ "boot_targets_usb",           test_boot_targets_usb },
		{ "boot_targets_network",       test_boot_targets_network },
		{ "boot_targets_safe",          test_boot_targets_safe },
		{ "bootcmd_network",            test_bootcmd_network },
		{ "altbootcmd_network",         test_altbootcmd_network },
		{ "bootfile_present",           test_bootfile_present },
		{ "serverip_present",           test_serverip_present },
		{ "ipaddr_present",             test_ipaddr_present },
		{ "factory_reset_var",          test_factory_reset_var },
		{ "reset_to_defaults_var",      test_reset_to_defaults_var },
		{ "resetenv_var",               test_resetenv_var },
		{ "eraseenv_var",               test_eraseenv_var },
		{ "bootcmd_factory_reset",      test_bootcmd_factory_reset },
		{ "multiple_issues",            test_multiple_issues },
	};
	return ela_run_test_suite("uboot_validate_env_security_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
