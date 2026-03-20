// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_IMAGE_SCAN_UTIL_H
#define ELA_UBOOT_IMAGE_SCAN_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Validate a FIT image header at *p.  abs_off is the byte offset of *p
 * within the device; dev_size is the device's total size in bytes.
 */
bool ela_uboot_image_validate_fit_header(const uint8_t *p,
					 uint64_t abs_off,
					 uint64_t dev_size);

/*
 * Validate a legacy uImage header at *p.  crc32_table must be
 * a 256-entry table initialised with ela_crc32_init().
 */
bool ela_uboot_image_validate_uimage_header(const uint8_t *p,
					    uint64_t abs_off,
					    uint64_t dev_size,
					    const uint32_t *crc32_table);

/*
 * Walk a FIT/FDT blob of blob_size bytes looking for a "load" property.
 * On success returns true and writes the load address to *addr_out.
 * Optionally writes the byte offset of the first U-Boot image payload to
 * *uboot_off_out and sets *uboot_off_found_out.
 */
bool ela_uboot_image_fit_find_load_address(const uint8_t *blob,
					   size_t blob_size,
					   uint32_t *addr_out,
					   uint64_t *uboot_off_out,
					   bool *uboot_off_found_out);

#endif /* ELA_UBOOT_IMAGE_SCAN_UTIL_H */
