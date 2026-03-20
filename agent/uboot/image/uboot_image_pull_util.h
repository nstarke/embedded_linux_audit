// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_IMAGE_PULL_UTIL_H
#define ELA_UBOOT_IMAGE_PULL_UTIL_H

#include <stddef.h>
#include <stdint.h>

/*
 * Inspect a 64-byte image header and determine the image type and total
 * byte count.  abs_off and dev_size are used for boundary validation.
 * crc32_table must be a 256-entry table initialised with ela_crc32_init().
 *
 * Returns:
 *   0   success; *total_size_out is set
 *  -1   null argument or unknown magic bytes
 *  -2   uImage magic detected but header validation failed
 *  -3   FIT magic detected but header validation failed
 */
int ela_uboot_image_pull_detect_size(const uint8_t *hdr,
				     uint64_t abs_off,
				     uint64_t dev_size,
				     const uint32_t *crc32_table,
				     uint64_t *total_size_out);

/*
 * Build the file path string "<dev>@0x<offset>.bin" into buf[buflen].
 *
 * Returns:
 *   0   success; buf is NUL-terminated and fully written
 *  -1   buf is NULL or buflen is 0
 *   1   output was truncated (buflen too small)
 */
int ela_uboot_image_pull_build_file_path(const char *dev, uint64_t offset,
					 char *buf, size_t buflen);

#endif /* ELA_UBOOT_IMAGE_PULL_UTIL_H */
