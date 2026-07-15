// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_eth_util.h"
#include "test_harness.h"

#include <string.h>

static void test_firmware_driver_map(void)
{
	/* mailbox/admin-queue drivers map to a class-directed target */
	ELA_ASSERT_STR_EQ("bnxt", eth_target_for_driver("bnxt_en"));
	ELA_ASSERT_STR_EQ("bnxt", eth_target_for_driver("bnxt"));
	ELA_ASSERT_STR_EQ("i40e", eth_target_for_driver("i40e"));
	ELA_ASSERT_STR_EQ("ice", eth_target_for_driver("ice"));
	ELA_ASSERT_STR_EQ("cxgb4", eth_target_for_driver("cxgb4"));
	ELA_ASSERT_STR_EQ("mlx5", eth_target_for_driver("mlx5_core"));
	ELA_ASSERT_STR_EQ("mlx5", eth_target_for_driver("mlx5"));
}

static void test_unsupported_drivers(void)
{
	/* commodity NICs with no firmware command interface: blind-only */
	ELA_ASSERT_TRUE(eth_target_for_driver("e1000e") == NULL);
	ELA_ASSERT_TRUE(eth_target_for_driver("igb") == NULL);
	ELA_ASSERT_TRUE(eth_target_for_driver("ixgbe") == NULL);
	ELA_ASSERT_TRUE(eth_target_for_driver("r8169") == NULL);
	ELA_ASSERT_TRUE(eth_target_for_driver("tg3") == NULL);
	ELA_ASSERT_TRUE(eth_target_for_driver("virtio_net") == NULL);
	ELA_ASSERT_TRUE(eth_target_for_driver("") == NULL);
	ELA_ASSERT_TRUE(eth_target_for_driver(NULL) == NULL);
}

static void test_uses_kmod(void)
{
	/* every firmware target injects through the shim */
	ELA_ASSERT_TRUE(eth_target_uses_kmod("bnxt"));
	ELA_ASSERT_TRUE(eth_target_uses_kmod("i40e"));
	ELA_ASSERT_TRUE(eth_target_uses_kmod("ice"));
	ELA_ASSERT_TRUE(eth_target_uses_kmod("cxgb4"));
	ELA_ASSERT_TRUE(eth_target_uses_kmod("mlx5"));
	/* the blind ioctl target does not */
	ELA_ASSERT_FALSE(eth_target_uses_kmod("ethtool-generic"));
	ELA_ASSERT_FALSE(eth_target_uses_kmod(NULL));
}

int run_linux_eth_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "map/firmware_drivers", test_firmware_driver_map },
		{ "map/unsupported", test_unsupported_drivers },
		{ "map/uses_kmod", test_uses_kmod },
	};

	return ela_run_test_suite("linux_eth_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
