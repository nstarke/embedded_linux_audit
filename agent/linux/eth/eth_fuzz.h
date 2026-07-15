// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Ethernet NIC fuzz targets. They ride the same class-directed fuzz engine as
 * the WLAN targets (grammar, mutation, loop, remote crash stream) declared in
 * wlan_fuzz.h -- that engine is NIC-agnostic despite the wlan_ prefix; only the
 * targets here are ethernet-specific.
 *
 * ethtool-generic is the broad blind target (SIOCETHTOOL ioctls, any NIC, by
 * interface name, host kernel driver). The rest are class-directed firmware
 * command targets injected through the ela_kmod shim (PCIe mailbox/admin-queue
 * NICs), analogous to the ath10k/mt76 WLAN shim targets.
 */
#ifndef ETH_FUZZ_H
#define ETH_FUZZ_H

#include "linux/wlan/wlan_fuzz.h"

/* Blind ethtool ioctl fuzzer, addressed by interface name. */
struct target *target_ethtool_generic(const char *iface);

/* Firmware-command targets via the ela_kmod shim. */
struct target *target_bnxt(void);	/* Broadcom NetXtreme HWRM        */
struct target *target_i40e(void);	/* Intel 700-series Admin Queue   */
struct target *target_ice(void);	/* Intel E800-series Admin Queue  */
struct target *target_cxgb4(void);	/* Chelsio T4/T5/T6 FW_CMD        */
struct target *target_mlx5(void);	/* Mellanox ConnectX cmdif        */

#endif
