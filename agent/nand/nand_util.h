// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_NAND_UTIL_H
#define ELA_NAND_UTIL_H

#include <stddef.h>
#include <stdint.h>

struct ela_nand_candidate {
	char mtd_name[64];
	uint32_t mtd_index;
	uint32_t erasesize;
	uint64_t size;
};

int ela_nand_select_dump_candidate(const struct ela_nand_candidate *candidates,
				   size_t count, size_t *selected,
				   char *errbuf, size_t errbuf_len);
int ela_nand_parse_device_index(const char *text, size_t *index,
				char *errbuf, size_t errbuf_len);

#endif
