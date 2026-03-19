// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_image_list_commands_util.h"

void ela_uboot_image_list_select_payload(const uint8_t *blob,
					 size_t blob_len,
					 bool uboot_off_found,
					 uint64_t uboot_off,
					 const uint8_t **payload_out,
					 size_t *payload_len_out)
{
	if (!payload_out || !payload_len_out)
		return;

	if (uboot_off_found && uboot_off < (uint64_t)blob_len) {
		*payload_out = blob + (size_t)uboot_off;
		*payload_len_out = blob_len - (size_t)uboot_off;
	} else {
		*payload_out = blob;
		*payload_len_out = blob_len;
	}
}
