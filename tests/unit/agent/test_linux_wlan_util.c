// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_wlan_util.h"
#include "test_harness.h"

#include <string.h>

static void test_usb_drivers_map(void)
{
	ELA_ASSERT_STR_EQ("ath9k-htc", wlan_target_for_driver("ath9k_htc", "usb"));
	ELA_ASSERT_STR_EQ("carl9170", wlan_target_for_driver("carl9170", "usb"));
	ELA_ASSERT_STR_EQ("mt7601u", wlan_target_for_driver("mt7601u", "usb"));
	ELA_ASSERT_STR_EQ("mwifiex-usb", wlan_target_for_driver("mwifiex_usb", "usb"));
	ELA_ASSERT_STR_EQ("rtl8xxxu", wlan_target_for_driver("rtl8xxxu", "usb"));
}

static void test_shim_drivers_any_bus(void)
{
	/* ath10k/11k/12k, brcmfmac go through the kmod shim regardless of bus */
	ELA_ASSERT_STR_EQ("ath10k", wlan_target_for_driver("ath10k_pci", "pci"));
	ELA_ASSERT_STR_EQ("ath10k", wlan_target_for_driver("ath10k_sdio", "sdio"));
	ELA_ASSERT_STR_EQ("ath10k", wlan_target_for_driver("ath10k_usb", "usb"));
	ELA_ASSERT_STR_EQ("ath11k", wlan_target_for_driver("ath11k_pci", "pci"));
	ELA_ASSERT_STR_EQ("ath11k", wlan_target_for_driver("ath11k_ahb", "platform"));
	ELA_ASSERT_STR_EQ("ath12k", wlan_target_for_driver("ath12k_pci", "pci"));
	ELA_ASSERT_STR_EQ("brcmfmac", wlan_target_for_driver("brcmfmac", "sdio"));
	ELA_ASSERT_STR_EQ("brcmfmac", wlan_target_for_driver("brcmfmac", "pci"));

	ELA_ASSERT_TRUE(wlan_target_uses_kmod("ath10k"));
	ELA_ASSERT_TRUE(wlan_target_uses_kmod("ath11k"));
	ELA_ASSERT_TRUE(wlan_target_uses_kmod("ath12k"));
	ELA_ASSERT_TRUE(wlan_target_uses_kmod("mt76"));
	ELA_ASSERT_TRUE(wlan_target_uses_kmod("brcmfmac"));
	ELA_ASSERT_FALSE(wlan_target_uses_kmod("rtl8xxxu"));
	ELA_ASSERT_FALSE(wlan_target_uses_kmod(NULL));
}

static void test_mt76_connac_vs_mt7601u(void)
{
	/* mt7601u is the usbfs target; connac chips map to the shim mt76 target */
	ELA_ASSERT_STR_EQ("mt7601u", wlan_target_for_driver("mt7601u", "usb"));
	ELA_ASSERT_STR_EQ("mt76", wlan_target_for_driver("mt7921e", "pci"));
	ELA_ASSERT_STR_EQ("mt76", wlan_target_for_driver("mt7915e", "pci"));
	ELA_ASSERT_STR_EQ("mt76", wlan_target_for_driver("mt7996e", "pci"));
	ELA_ASSERT_STR_EQ("mt76", wlan_target_for_driver("mt7615e", "pci"));
	ELA_ASSERT_STR_EQ("mt76", wlan_target_for_driver("mt7663s", "sdio"));
}

static void test_rtw88_usb_only(void)
{
	/* rtw88 USB variants are supported; PCIe variants are not (yet) */
	ELA_ASSERT_STR_EQ("rtw88-usb", wlan_target_for_driver("rtw_8822bu", "usb"));
	ELA_ASSERT_STR_EQ("rtw88-usb", wlan_target_for_driver("rtw_8821cu", "usb"));
	ELA_ASSERT_TRUE(wlan_target_for_driver("rtw_8822be", "pci") == NULL);
}

static void test_unsupported_and_edge(void)
{
	ELA_ASSERT_TRUE(wlan_target_for_driver("iwlwifi", "pci") == NULL);
	ELA_ASSERT_TRUE(wlan_target_for_driver("mwifiex_pcie", "pci") == NULL);
	ELA_ASSERT_TRUE(wlan_target_for_driver("mt76x2u", "usb") == NULL);
	ELA_ASSERT_TRUE(wlan_target_for_driver(NULL, "usb") == NULL);
	ELA_ASSERT_TRUE(wlan_target_for_driver("", "usb") == NULL);
}

int run_linux_wlan_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "map/usb_drivers", test_usb_drivers_map },
		{ "map/shim_drivers", test_shim_drivers_any_bus },
		{ "map/mt76_vs_mt7601u", test_mt76_connac_vs_mt7601u },
		{ "map/rtw88_usb_only", test_rtw88_usb_only },
		{ "map/unsupported_edge", test_unsupported_and_edge },
	};

	return ela_run_test_suite("linux_wlan_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
