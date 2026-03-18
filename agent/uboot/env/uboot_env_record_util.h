// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_ENV_RECORD_UTIL_H
#define ELA_UBOOT_ENV_RECORD_UTIL_H

#include <stdbool.h>
#include <stddef.h>

const char *ela_uboot_env_candidate_mode(bool bruteforce,
					 bool crc_ok_std,
					 bool crc_ok_redund);
size_t ela_uboot_env_data_offset(bool crc_ok_std, bool crc_ok_redund);

#endif
