// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "orom/orom_pull_cmd_common.h"

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

int efi_orom_main(int argc, char **argv)
{
	return orom_group_main("efi", argc, argv);
}

/* LCOV_EXCL_STOP */
