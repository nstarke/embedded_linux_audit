// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Pure mapping helpers for `linux eth list`: given a bound kernel driver name,
 * report which `linux eth fuzz` firmware-command target (if any) covers it.
 * Side-effect-free so they are unit-testable without hardware.
 *
 * Unlike WLAN NICs, most ethernet NICs expose no host->firmware command
 * grammar -- they are driven by descriptor rings + MMIO. Only the subset with
 * a firmware mailbox / admin-queue command interface gets a class-directed
 * target here; every NIC is still reachable by the blind `ethtool-generic`
 * target (fuzzes the driver's SIOCETHTOOL ioctl handlers), which is addressed
 * by interface name, not driver, so it is not mapped here.
 */
#ifndef LINUX_ETH_UTIL_H
#define LINUX_ETH_UTIL_H

/*
 * Return the `linux eth fuzz --target` name for a NIC bound to `driver`, or
 * NULL if no class-directed firmware target covers it. Maps the mailbox/AQ
 * drivers: bnxt_en->bnxt (HWRM), i40e/ice (Admin Queue), cxgb4 (FW_CMD),
 * mlx5_core->mlx5 (cmdif).
 */
const char *eth_target_for_driver(const char *driver);

/* 1 if the target injects through the ela_kmod kernel shim (all firmware
 * targets), 0 for the userspace ioctl target (ethtool-generic). */
int eth_target_uses_kmod(const char *target);

#endif
