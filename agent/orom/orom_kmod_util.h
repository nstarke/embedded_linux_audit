// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_OROM_KMOD_UTIL_H
#define ELA_OROM_KMOD_UTIL_H

#include <stddef.h>
#include <stdint.h>

struct ela_orom_kmod_candidate {
	uint32_t domain;
	uint32_t bus;
	uint32_t device;
	uint32_t function;
	uint64_t size;
};

int ela_orom_kmod_select_candidate(
	const struct ela_orom_kmod_candidate *candidates, size_t count,
	size_t *selected, char *errbuf, size_t errbuf_sz);
int ela_orom_kmod_parse_index(const char *text, size_t *index,
			      char *errbuf, size_t errbuf_sz);

#endif
