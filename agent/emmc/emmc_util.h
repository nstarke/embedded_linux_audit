// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_EMMC_UTIL_H
#define ELA_EMMC_UTIL_H

#include <stddef.h>
#include <stdint.h>

struct ela_emmc_candidate {
	char disk_name[32];
	uint32_t major;
	uint32_t minor;
	uint32_t logical_block_size;
	uint64_t size;
};

int ela_emmc_select_dump_candidate(const struct ela_emmc_candidate *candidates,
				   size_t count, size_t *selected,
				   char *errbuf, size_t errbuf_sz);
int ela_emmc_parse_device_index(const char *text, size_t *index,
				char *errbuf, size_t errbuf_sz);

#endif
