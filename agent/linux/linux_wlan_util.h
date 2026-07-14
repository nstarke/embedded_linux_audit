// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Pure mapping helpers for `linux wlan list`: given a bound kernel driver name
 * and bus type, report which `linux wlan fuzz` target (if any) covers it.
 * Kept side-effect-free so they are unit-testable without hardware.
 */
#ifndef LINUX_WLAN_UTIL_H
#define LINUX_WLAN_UTIL_H

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

#endif
