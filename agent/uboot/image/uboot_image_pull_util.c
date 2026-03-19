// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_image_pull_util.h"
#include "uboot_image_scan_util.h"
#include "uboot_image_internal.h"
#include "embedded_linux_audit_cmd.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int ela_uboot_image_pull_detect_size(const uint8_t *hdr,
				     uint64_t abs_off,
				     uint64_t dev_size,
				     const uint32_t *crc32_table,
				     uint64_t *total_size_out)
{
	if (!hdr || !crc32_table || !total_size_out)
		return -1;

	if (!memcmp(hdr, "\x27\x05\x19\x56", 4)) {
		if (!ela_uboot_image_validate_uimage_header(hdr, abs_off,
							    dev_size,
							    crc32_table))
			return -2;
		*total_size_out = UIMAGE_HDR_SIZE + ela_read_be32(hdr + 12);
		return 0;
	}

	if (!memcmp(hdr, "\xD0\x0D\xFE\xED", 4)) {
		if (!ela_uboot_image_validate_fit_header(hdr, abs_off, dev_size))
			return -3;
		*total_size_out = ela_read_be32(hdr + 4);
		return 0;
	}

	return -1;
}

int ela_uboot_image_pull_build_file_path(const char *dev, uint64_t offset,
					 char *buf, size_t buflen)
{
	int n;

	if (!buf || !buflen)
		return -1;

	n = snprintf(buf, buflen, "%s@0x%jx.bin",
		     dev ? dev : "", (uintmax_t)offset);
	if (n < 0 || (size_t)n >= buflen)
		return 1;
	return 0;
}
