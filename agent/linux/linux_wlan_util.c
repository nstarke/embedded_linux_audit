// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux/linux_wlan_util.h"

#include <string.h>

int wlan_name_is_wireless_hint(const char *name)
{
	static const char *const prefixes[] = {
		"wlan", "wlp", "wlx", "wifi", "ath", "ra", "mlan",
	};
	size_t i;

	if (!name || !*name)
		return 0;
	for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
		if (!strncmp(name, prefixes[i], strlen(prefixes[i])))
			return 1;
	}
	return 0;
}

enum wlan_wireless_confidence wlan_classify_wireless(int has_phy80211,
						     int has_wireless_dir,
						     int in_proc_wireless,
						     int uevent_devtype_wlan,
						     const char *name)
{
	if (has_phy80211 || has_wireless_dir || in_proc_wireless ||
	    uevent_devtype_wlan)
		return WLAN_WIRELESS_CONFIRMED;
	if (wlan_name_is_wireless_hint(name))
		return WLAN_WIRELESS_NAME;
	return WLAN_WIRELESS_NO;
}

int wlan_uevent_value(const char *uevent_text, const char *key, char *out,
		      size_t outsz)
{
	size_t keylen;
	const char *p;

	if (!uevent_text || !key || !*key || !out || outsz == 0)
		return -1;
	keylen = strlen(key);

	/* Walk line by line; `p` is always at a line start. */
	for (p = uevent_text; *p;) {
		if (!strncmp(p, key, keylen) && p[keylen] == '=') {
			const char *v = p + keylen + 1;
			const char *end = v;
			size_t len;

			while (*end && *end != '\n')
				end++;
			len = (size_t)(end - v);
			if (len >= outsz)
				len = outsz - 1;
			memcpy(out, v, len);
			out[len] = '\0';
			return 0;
		}
		while (*p && *p != '\n')
			p++;
		if (*p == '\n')
			p++;
	}
	return -1;
}

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

/* A single 1-4 digit hex halfword; *out set on success. NULL end means the
 * whole [s,e) span must be consumed. Returns 0 ok, -1 on empty/overflow/junk. */
static int parse_hex16(const char *s, const char *e, uint16_t *out)
{
	unsigned long v = 0;

	if (s == e)
		return -1;
	for (; s < e; s++) {
		int d;

		if (*s >= '0' && *s <= '9')
			d = *s - '0';
		else if (*s >= 'a' && *s <= 'f')
			d = *s - 'a' + 10;
		else if (*s >= 'A' && *s <= 'F')
			d = *s - 'A' + 10;
		else
			return -1;
		v = v * 16 + (unsigned long)d;
		if (v > 0xFFFF)
			return -1;
	}
	*out = (uint16_t)v;
	return 0;
}

int wlan_parse_usb_id(const char *s, uint16_t *vid, uint16_t *pid)
{
	const char *colon;

	if (!s || !vid || !pid)
		return -1;
	colon = strchr(s, ':');
	if (!colon)
		return -1;
	if (parse_hex16(s, colon, vid) != 0)
		return -1;

	/* product half: "*" or empty => wildcard (0 = match any product) */
	if (colon[1] == '\0' || (colon[1] == '*' && colon[2] == '\0')) {
		*pid = 0;
		return 0;
	}
	return parse_hex16(colon + 1, colon + 1 + strlen(colon + 1), pid);
}
