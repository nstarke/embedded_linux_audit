// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_VALIDATE_CRC32_UTIL_H
#define ELA_UBOOT_VALIDATE_CRC32_UTIL_H

#include <stddef.h>

struct embedded_linux_audit_input;

int ela_uboot_validate_crc32_cmp(const struct embedded_linux_audit_input *input,
				 char *message, size_t message_len);

#endif
