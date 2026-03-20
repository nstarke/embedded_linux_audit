// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_validate_crc32_util.h"
#include "embedded_linux_audit_cmd.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

int ela_uboot_validate_crc32_cmp(const struct embedded_linux_audit_input *input,
				 char *message, size_t message_len)
{
	uint32_t stored_le;
	uint32_t stored_be;
	uint32_t calc_std;
	uint32_t calc_redund = 0;

	if (!input || !input->data || !input->crc32_table || input->data_len < 8) {
		if (message && message_len)
			snprintf(message, message_len, "input too small (need at least 8 bytes)");
		return -1;
	}

	stored_le = (uint32_t)input->data[0] |
		((uint32_t)input->data[1] << 8) |
		((uint32_t)input->data[2] << 16) |
		((uint32_t)input->data[3] << 24);
	stored_be = ela_read_be32(input->data);

	calc_std = ela_crc32_calc(input->crc32_table, input->data + 4, input->data_len - 4);
	if (input->data_len > 5)
		calc_redund = ela_crc32_calc(input->crc32_table, input->data + 5, input->data_len - 5);

	if (calc_std == stored_le || calc_std == stored_be) {
		if (message && message_len) {
			snprintf(message, message_len,
				 "standard env CRC32 matched (%s-endian), offset=0x%jx size=0x%zx",
				 (calc_std == stored_le) ? "LE" : "BE",
				 (uintmax_t)input->offset,
				 input->data_len);
		}
		return 0;
	}

	if (input->data_len > 5 && (calc_redund == stored_le || calc_redund == stored_be)) {
		if (message && message_len) {
			snprintf(message, message_len,
				 "redundant env CRC32 matched (%s-endian), offset=0x%jx size=0x%zx",
				 (calc_redund == stored_le) ? "LE" : "BE",
				 (uintmax_t)input->offset,
				 input->data_len);
		}
		return 0;
	}

	if (message && message_len) {
		snprintf(message, message_len,
			 "crc32 mismatch: stored_le=0x%08x stored_be=0x%08x calc_std=0x%08x calc_redund=0x%08x",
			 stored_le, stored_be, calc_std, calc_redund);
	}

	return 1;
}
