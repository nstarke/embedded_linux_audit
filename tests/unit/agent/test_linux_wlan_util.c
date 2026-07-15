// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_wlan_util.h"
#include "../../../agent/linux/wlan/wlan_fuzz_stream_fmt.h"
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

static void test_name_hint(void)
{
	/* conventional wireless prefixes */
	ELA_ASSERT_TRUE(wlan_name_is_wireless_hint("wlan0"));
	ELA_ASSERT_TRUE(wlan_name_is_wireless_hint("wlp2s0"));
	ELA_ASSERT_TRUE(wlan_name_is_wireless_hint("wlx001122334455"));
	ELA_ASSERT_TRUE(wlan_name_is_wireless_hint("wifi0"));
	ELA_ASSERT_TRUE(wlan_name_is_wireless_hint("ath0"));
	ELA_ASSERT_TRUE(wlan_name_is_wireless_hint("ra0"));
	ELA_ASSERT_TRUE(wlan_name_is_wireless_hint("mlan0"));

	/* wired / unrelated names must not match */
	ELA_ASSERT_FALSE(wlan_name_is_wireless_hint("eth0"));
	ELA_ASSERT_FALSE(wlan_name_is_wireless_hint("enp0s3"));
	ELA_ASSERT_FALSE(wlan_name_is_wireless_hint("lo"));
	ELA_ASSERT_FALSE(wlan_name_is_wireless_hint("br0"));
	ELA_ASSERT_FALSE(wlan_name_is_wireless_hint(""));
	ELA_ASSERT_FALSE(wlan_name_is_wireless_hint(NULL));
}

static void test_classify_wireless(void)
{
	/* any single kernel marker => CONFIRMED, regardless of name */
	ELA_ASSERT_TRUE(wlan_classify_wireless(1, 0, 0, 0, "eth0") ==
			WLAN_WIRELESS_CONFIRMED);	/* phy80211 */
	ELA_ASSERT_TRUE(wlan_classify_wireless(0, 1, 0, 0, "eth0") ==
			WLAN_WIRELESS_CONFIRMED);	/* wireless/ */
	ELA_ASSERT_TRUE(wlan_classify_wireless(0, 0, 1, 0, "eth0") ==
			WLAN_WIRELESS_CONFIRMED);	/* /proc/net/wireless */
	ELA_ASSERT_TRUE(wlan_classify_wireless(0, 0, 0, 1, "eth0") ==
			WLAN_WIRELESS_CONFIRMED);	/* DEVTYPE=wlan */

	/* no marker but a wireless name => NAME (proprietary-stack fallback) */
	ELA_ASSERT_TRUE(wlan_classify_wireless(0, 0, 0, 0, "wlan0") ==
			WLAN_WIRELESS_NAME);
	ELA_ASSERT_TRUE(wlan_classify_wireless(0, 0, 0, 0, "ath0") ==
			WLAN_WIRELESS_NAME);

	/* no marker and a wired name => NO */
	ELA_ASSERT_TRUE(wlan_classify_wireless(0, 0, 0, 0, "eth0") ==
			WLAN_WIRELESS_NO);
	ELA_ASSERT_TRUE(wlan_classify_wireless(0, 0, 0, 0, NULL) ==
			WLAN_WIRELESS_NO);
}

static void test_uevent_value(void)
{
	static const char ue[] =
		"DRIVER=ath10k_pci\n"
		"OF_NAME=wifi\n"
		"DEVTYPE=wlan\n"
		"MODALIAS=pci:v0000168Cd0000003E\n";
	char val[64];

	ELA_ASSERT_TRUE(wlan_uevent_value(ue, "DRIVER", val, sizeof(val)) == 0);
	ELA_ASSERT_STR_EQ("ath10k_pci", val);
	ELA_ASSERT_TRUE(wlan_uevent_value(ue, "DEVTYPE", val, sizeof(val)) == 0);
	ELA_ASSERT_STR_EQ("wlan", val);
	/* last line (no trailing key match issues) */
	ELA_ASSERT_TRUE(wlan_uevent_value(ue, "MODALIAS", val, sizeof(val)) == 0);
	ELA_ASSERT_STR_EQ("pci:v0000168Cd0000003E", val);

	/* absent key, and a prefix that is not a whole key, both fail */
	ELA_ASSERT_TRUE(wlan_uevent_value(ue, "SUBSYSTEM", val, sizeof(val)) != 0);
	ELA_ASSERT_TRUE(wlan_uevent_value(ue, "DRIV", val, sizeof(val)) != 0);

	/* invalid args */
	ELA_ASSERT_TRUE(wlan_uevent_value(NULL, "DRIVER", val, sizeof(val)) != 0);
	ELA_ASSERT_TRUE(wlan_uevent_value(ue, "DRIVER", val, 0) != 0);

	/* value truncated into a short buffer, still NUL-terminated */
	{
		char small[5];

		ELA_ASSERT_TRUE(wlan_uevent_value(ue, "DRIVER", small,
						  sizeof(small)) == 0);
		ELA_ASSERT_STR_EQ("ath1", small);
	}
}

static void test_parse_usb_id(void)
{
	uint16_t vid = 0xdead, pid = 0xbeef;

	/* canonical lsusb form */
	ELA_ASSERT_TRUE(wlan_parse_usb_id("0bda:8179", &vid, &pid) == 0);
	ELA_ASSERT_TRUE(vid == 0x0bda);
	ELA_ASSERT_TRUE(pid == 0x8179);

	/* uppercase hex, and short (1-digit) halves */
	ELA_ASSERT_TRUE(wlan_parse_usb_id("ABCD:F", &vid, &pid) == 0);
	ELA_ASSERT_TRUE(vid == 0xABCD);
	ELA_ASSERT_TRUE(pid == 0x000F);

	/* product wildcard: '*' or empty => pid 0 (match any) */
	ELA_ASSERT_TRUE(wlan_parse_usb_id("0bda:*", &vid, &pid) == 0);
	ELA_ASSERT_TRUE(vid == 0x0bda && pid == 0);
	ELA_ASSERT_TRUE(wlan_parse_usb_id("0bda:", &vid, &pid) == 0);
	ELA_ASSERT_TRUE(vid == 0x0bda && pid == 0);

	/* malformed: no colon, empty vendor, non-hex, overflow, trailing junk */
	ELA_ASSERT_TRUE(wlan_parse_usb_id("0bda8179", &vid, &pid) != 0);
	ELA_ASSERT_TRUE(wlan_parse_usb_id(":8179", &vid, &pid) != 0);
	ELA_ASSERT_TRUE(wlan_parse_usb_id("0bZa:8179", &vid, &pid) != 0);
	ELA_ASSERT_TRUE(wlan_parse_usb_id("10bda:8179", &vid, &pid) != 0);
	ELA_ASSERT_TRUE(wlan_parse_usb_id("0bda:8179x", &vid, &pid) != 0);
	ELA_ASSERT_TRUE(wlan_parse_usb_id("0bda:1ffff", &vid, &pid) != 0);
	ELA_ASSERT_TRUE(wlan_parse_usb_id(NULL, &vid, &pid) != 0);
}

static void test_valid_iface(void)
{
	/* typical interface names */
	ELA_ASSERT_TRUE(wlan_valid_iface("wlan0"));
	ELA_ASSERT_TRUE(wlan_valid_iface("wlp3s0"));
	ELA_ASSERT_TRUE(wlan_valid_iface("ath0"));
	ELA_ASSERT_TRUE(wlan_valid_iface("a"));
	ELA_ASSERT_TRUE(wlan_valid_iface("123456789012345"));	/* 15 chars */

	/* rejected: empty, too long (16), slash, whitespace, control char */
	ELA_ASSERT_FALSE(wlan_valid_iface(""));
	ELA_ASSERT_FALSE(wlan_valid_iface("1234567890123456"));	/* 16 chars */
	ELA_ASSERT_FALSE(wlan_valid_iface("wlan/0"));
	ELA_ASSERT_FALSE(wlan_valid_iface("wlan 0"));
	ELA_ASSERT_FALSE(wlan_valid_iface("wlan\t0"));
	ELA_ASSERT_FALSE(wlan_valid_iface("../etc"));
	ELA_ASSERT_FALSE(wlan_valid_iface(NULL));
}

static void test_stream_case_line(void)
{
	static const uint8_t p[] = { 0x40, 0x05, 0x00, 0x01 };
	char out[64];
	int n;

	/* msg + hex + note, matching the on-disk crash-file grammar */
	n = wlan_fuzz_format_case_line(out, sizeof(out), "SIWESSID", p, 4,
				       "buf=len:4");
	ELA_ASSERT_TRUE(n > 0);
	ELA_ASSERT_STR_EQ("SIWESSID 40050001 #buf=len:4", out);

	/* empty note => no trailing " #" */
	n = wlan_fuzz_format_case_line(out, sizeof(out), "SIWMODE", p, 1, "");
	ELA_ASSERT_STR_EQ("SIWMODE 40", out);
	ELA_ASSERT_TRUE(n == 10);

	/* zero-length payload is valid (e.g. a scan trigger) */
	n = wlan_fuzz_format_case_line(out, sizeof(out), "SIWSCAN", NULL, 0, NULL);
	ELA_ASSERT_STR_EQ("SIWSCAN ", out);

	/* newlines in the note are flattened to keep one line per case */
	wlan_fuzz_format_case_line(out, sizeof(out), "X", p, 1, "a\nb");
	ELA_ASSERT_STR_EQ("X 40 #a b", out);

	/* invalid args and a too-small buffer are rejected */
	ELA_ASSERT_TRUE(wlan_fuzz_format_case_line(out, sizeof(out), NULL, p, 1,
						   NULL) == -1);
	ELA_ASSERT_TRUE(wlan_fuzz_format_case_line(out, sizeof(out), "X", NULL,
						   3, NULL) == -1);
	ELA_ASSERT_TRUE(wlan_fuzz_format_case_line(out, 4, "SIWESSID", p, 4,
						   NULL) == -1);

	/* payload is truncated cleanly when the buffer can't hold all hex */
	n = wlan_fuzz_format_case_line(out, 8, "AB", p, 4, NULL);
	ELA_ASSERT_STR_EQ("AB 4005", out);	/* "AB " + 2 bytes, NUL-terminated */
	ELA_ASSERT_TRUE(n == 7);
}

int run_linux_wlan_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "map/usb_drivers", test_usb_drivers_map },
		{ "map/shim_drivers", test_shim_drivers_any_bus },
		{ "map/mt76_vs_mt7601u", test_mt76_connac_vs_mt7601u },
		{ "map/rtw88_usb_only", test_rtw88_usb_only },
		{ "map/unsupported_edge", test_unsupported_and_edge },
		{ "detect/name_hint", test_name_hint },
		{ "detect/classify_wireless", test_classify_wireless },
		{ "detect/uevent_value", test_uevent_value },
		{ "parse/usb_id", test_parse_usb_id },
		{ "parse/valid_iface", test_valid_iface },
		{ "stream/case_line", test_stream_case_line },
	};

	return ela_run_test_suite("linux_wlan_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
