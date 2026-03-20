// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_IMAGE_FIND_ADDRESS_UTIL_H
#define ELA_UBOOT_IMAGE_FIND_ADDRESS_UTIL_H

#include <stddef.h>
#include <stdint.h>

/*
 * Read the load address field from a legacy uImage header.
 * The load address is stored as a big-endian uint32 at byte offset 16.
 */
uint32_t ela_uboot_image_uimage_read_load_addr(const uint8_t *hdr);

/*
 * Format a 32-bit load address as "0x%08x" into buf[buflen].
 * Returns  0 on success (fully written, NUL-terminated),
 *         -1 if buf is NULL or buflen is 0,
 *          1 if the output was truncated.
 */
int ela_uboot_image_find_format_addr32(uint32_t addr, char *buf, size_t buflen);

/*
 * Format a 64-bit byte offset as "0x%jx" into buf[buflen].
 * Returns  0 on success,
 *         -1 if buf is NULL or buflen is 0,
 *          1 if the output was truncated.
 */
int ela_uboot_image_find_format_offset(uint64_t off, char *buf, size_t buflen);

#endif /* ELA_UBOOT_IMAGE_FIND_ADDRESS_UTIL_H */
