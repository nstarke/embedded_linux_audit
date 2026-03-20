// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_VALIDATE_CMDLINE_INIT_UTIL_H
#define ELA_UBOOT_VALIDATE_CMDLINE_INIT_UTIL_H

#include <stdbool.h>
#include <stddef.h>

int ela_uboot_cmdline_init_writeability_result(bool has_init,
					       bool init_valid,
					       bool writeable,
					       const char *init_value,
					       const char *device,
					       char *message,
					       size_t message_len);

#endif
