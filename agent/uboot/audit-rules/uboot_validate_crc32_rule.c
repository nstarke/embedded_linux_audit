// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/audit-rules/uboot_validate_crc32_util.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

static int run_validate_crc32(const struct embedded_linux_audit_input *input, char *message, size_t message_len)
{
	int env_scan_rc;

	env_scan_rc = uboot_env_ensure_config();
	if (env_scan_rc != 0) {
		if (message && message_len)
			snprintf(message, message_len,
				 "uboot_env.config not found and env scan failed (rc=%d)", env_scan_rc);
		return -1;
	}

	return ela_uboot_validate_crc32_cmp(input, message, message_len);
}

static const struct embedded_linux_audit_rule uboot_validate_crc32_rule = {
	.name = "uboot_validate_crc32",
	.description = "Validate U-Boot environment CRC32 checksum (standard/redundant layouts)",
	.run = run_validate_crc32,
};

ELA_REGISTER_RULE(uboot_validate_crc32_rule);

/* LCOV_EXCL_STOP */
