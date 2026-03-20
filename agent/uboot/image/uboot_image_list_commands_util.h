// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_IMAGE_LIST_COMMANDS_UTIL_H
#define ELA_UBOOT_IMAGE_LIST_COMMANDS_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Given an image blob of blob_len bytes, compute the payload slice to pass
 * to command extraction.
 *
 * When uboot_off_found is true and uboot_off is strictly less than blob_len,
 * the payload starts at blob + uboot_off with length blob_len - uboot_off.
 * Otherwise the full blob is used.
 *
 * Writes to *payload_out and *payload_len_out only when both are non-NULL.
 */
void ela_uboot_image_list_select_payload(const uint8_t *blob,
					 size_t blob_len,
					 bool uboot_off_found,
					 uint64_t uboot_off,
					 const uint8_t **payload_out,
					 size_t *payload_len_out);

#endif /* ELA_UBOOT_IMAGE_LIST_COMMANDS_UTIL_H */
