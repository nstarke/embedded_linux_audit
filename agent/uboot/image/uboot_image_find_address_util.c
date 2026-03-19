// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_image_find_address_util.h"
#include "embedded_linux_audit_cmd.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

uint32_t ela_uboot_image_uimage_read_load_addr(const uint8_t *hdr)
{
	return ela_read_be32(hdr + 16);
}

int ela_uboot_image_find_format_addr32(uint32_t addr, char *buf, size_t buflen)
{
	int n;

	if (!buf || !buflen)
		return -1;

	n = snprintf(buf, buflen, "0x%08x", addr);
	if (n < 0 || (size_t)n >= buflen)
		return 1;
	return 0;
}

int ela_uboot_image_find_format_offset(uint64_t off, char *buf, size_t buflen)
{
	int n;

	if (!buf || !buflen)
		return -1;

	n = snprintf(buf, buflen, "0x%jx", (uintmax_t)off);
	if (n < 0 || (size_t)n >= buflen)
		return 1;
	return 0;
}
