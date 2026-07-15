// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux/linux_eth_util.h"

#include <string.h>

const char *eth_target_for_driver(const char *driver)
{
	if (!driver || !*driver)
		return NULL;

	/* Broadcom NetXtreme: HWRM command interface over a DMA mailbox. */
	if (!strcmp(driver, "bnxt_en") || !strcmp(driver, "bnxt"))
		return "bnxt";
	/* Intel 700/E800 series: firmware Admin Queue. */
	if (!strcmp(driver, "i40e"))
		return "i40e";
	if (!strcmp(driver, "ice"))
		return "ice";
	/* Chelsio T4/T5/T6: FW_CMD mailbox. */
	if (!strcmp(driver, "cxgb4"))
		return "cxgb4";
	/* Mellanox ConnectX: firmware command interface (cmdif). */
	if (!strcmp(driver, "mlx5_core") || !strcmp(driver, "mlx5"))
		return "mlx5";

	return NULL;
}

int eth_target_uses_kmod(const char *target)
{
	return target && (!strcmp(target, "bnxt") || !strcmp(target, "i40e") ||
			  !strcmp(target, "ice") || !strcmp(target, "cxgb4") ||
			  !strcmp(target, "mlx5"));
}
