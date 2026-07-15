// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Pure mapping helpers for `linux wlan list`: given a bound kernel driver name
 * and bus type, report which `linux wlan fuzz` target (if any) covers it.
 * Kept side-effect-free so they are unit-testable without hardware.
 */
#ifndef LINUX_WLAN_UTIL_H
#define LINUX_WLAN_UTIL_H

#include <stddef.h>
#include <stdint.h>

/*
 * Confidence that a netdev is a wireless NIC, strongest signal first.
 * CONFIRMED means the kernel exposed an explicit wireless marker (a phy80211
 * link, a wireless/ sysfs dir, a /proc/net/wireless row, or DEVTYPE=wlan).
 * NAME means no marker was found but the interface name matched a wireless
 * pattern -- the case for proprietary/stripped stacks that register no
 * cfg80211/WEXT node -- and callers should treat it as a guess. NO means the
 * interface is not wireless.
 */
enum wlan_wireless_confidence {
	WLAN_WIRELESS_NO = 0,
	WLAN_WIRELESS_NAME = 1,
	WLAN_WIRELESS_CONFIRMED = 2,
};

/*
 * Classify a netdev from the wireless signals gathered out of sysfs/procfs.
 * Any single CONFIRMED marker wins; failing all of them a matching `name`
 * yields NAME; otherwise NO. `name` may be NULL. Side-effect free so the
 * detection policy is unit-testable without hardware.
 */
enum wlan_wireless_confidence wlan_classify_wireless(int has_phy80211,
						     int has_wireless_dir,
						     int in_proc_wireless,
						     int uevent_devtype_wlan,
						     const char *name);

/*
 * 1 if `name` matches a conventional wireless interface-name pattern
 * (wlan*, wlp*, wlx*, wifi*, ath*, ra*, mlan*), else 0. Weak, last-resort
 * signal used only when no kernel marker is present.
 */
int wlan_name_is_wireless_hint(const char *name);

/*
 * Extract the value of `key` (e.g. "DRIVER" or "DEVTYPE") from uevent file
 * contents -- newline-separated KEY=VALUE lines -- into `out`. `key` must
 * match at the start of a line. Returns 0 on a match, -1 if the key is absent
 * or any argument is invalid. Used as a driver-name fallback when the
 * device/driver symlink is missing (common with out-of-tree modules).
 */
int wlan_uevent_value(const char *uevent_text, const char *key, char *out,
		      size_t outsz);

/*
 * Return the `linux wlan fuzz --target` name that supports a NIC bound to
 * `driver` on `bus` ("pci", "usb", "sdio", ...), or NULL if unsupported.
 * `bus` may be NULL/empty; it is only consulted where a driver spans buses
 * with different support (e.g. rtw88 USB vs PCIe).
 */
const char *wlan_target_for_driver(const char *driver, const char *bus);

/* 1 if the target injects through the ela_kmod kernel shim (ath10k/ath11k),
 * 0 if it drives the device directly through usbfs. */
int wlan_target_uses_kmod(const char *target);

/*
 * Parse a "VID:PID" USB id (hex, as lsupb/sysfs print it -- e.g. "0bda:8179")
 * into *vid and *pid. The product half may be "*" or empty for a wildcard,
 * yielding pid 0 (match any product for that vendor). Returns 0 on success,
 * -1 on a malformed id or invalid argument. Used by `wlan fuzz --target
 * usb-generic --usb-id <VID:PID>` to address a proprietary USB NIC that maps
 * to no class-directed target.
 */
int wlan_parse_usb_id(const char *s, uint16_t *vid, uint16_t *pid);

/*
 * 1 if `name` is a usable Linux network-interface name for the `wext-generic`
 * fuzz target: non-empty, at most 15 chars (IFNAMSIZ-1), and free of '/',
 * whitespace, and control characters. 0 otherwise. Guards the `--iface`
 * argument before it is copied into an ifreq.
 */
int wlan_valid_iface(const char *name);

#endif
