// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux/linux_wlan_util.h"

#include <string.h>

const char *wlan_target_for_driver(const char *driver, const char *bus)
{
	if (!driver || !*driver)
		return NULL;

	/* ath10k/11k/12k and brcmfmac reach firmware through the ela_kmod shim
	 * regardless of bus (PCIe/SDIO/USB), so bus is not consulted for them. */
	if (!strncmp(driver, "ath10k", 6))
		return "ath10k";
	if (!strncmp(driver, "ath11k", 6))
		return "ath11k";
	if (!strncmp(driver, "ath12k", 6))
		return "ath12k";
	if (!strcmp(driver, "brcmfmac"))
		return "brcmfmac";

	/* USB dongles driven directly through usbfs. mt7601u must be matched
	 * before the mt76 connac prefixes below (it is a distinct target). */
	if (!strcmp(driver, "ath9k_htc"))
		return "ath9k-htc";
	if (!strcmp(driver, "carl9170"))
		return "carl9170";
	if (!strcmp(driver, "mt7601u"))
		return "mt7601u";
	if (!strcmp(driver, "mwifiex_usb"))
		return "mwifiex-usb";
	if (!strcmp(driver, "rtl8xxxu"))
		return "rtl8xxxu";

	/* mt76 connac MCU chips via the shim: mt7615/mt7663 and the mt79xx
	 * family (mt7915/7916/7921/7925/7981/7986/7996). */
	if (!strncmp(driver, "mt79", 4) || !strncmp(driver, "mt7615", 6) ||
	    !strncmp(driver, "mt7663", 6))
		return "mt76";

	/* rtw88 has USB and PCIe variants (rtw_8822bu vs rtw_8822be); only the
	 * USB command grammar is supported today. */
	if ((!strncmp(driver, "rtw_", 4) || !strncmp(driver, "rtw88", 5)) &&
	    bus && !strcmp(bus, "usb"))
		return "rtw88-usb";

	return NULL;
}

int wlan_target_uses_kmod(const char *target)
{
	return target && (!strcmp(target, "ath10k") || !strcmp(target, "ath11k") ||
			  !strcmp(target, "ath12k") || !strcmp(target, "mt76") ||
			  !strcmp(target, "brcmfmac"));
}
