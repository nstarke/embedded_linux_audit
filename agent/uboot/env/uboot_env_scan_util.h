// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_ENV_SCAN_UTIL_H
#define ELA_UBOOT_ENV_SCAN_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ela_uboot_env_candidate {
	uint64_t cfg_off;
	bool crc_standard;
	bool crc_redundant;
};

int ela_uboot_env_add_or_merge_candidate(struct ela_uboot_env_candidate **cands,
					 size_t *count,
					 uint64_t cfg_off,
					 bool crc_standard,
					 bool crc_redundant);
bool ela_uboot_env_is_http_write_source(const char *s);
bool ela_uboot_env_should_report_redundant_pair(uint64_t prev,
						uint64_t curr,
						uint64_t erase_size,
						uint64_t sector_count);

#endif
