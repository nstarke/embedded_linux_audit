// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "spi_util.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int ela_spi_select_dump_candidate(const struct ela_spi_mtd_candidate *candidates,
				  size_t count, size_t *selected,
				  char *errbuf, size_t errbuf_len)
{
	size_t best = 0;
	size_t ties = 0;
	size_t i;

	if (!selected || (!candidates && count)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Invalid SPI dump candidate list");
		return -1;
	}
	if (!count) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len,
				 "No SPI-backed MTD devices were found");
		return -1;
	}

	for (i = 0; i < count; i++) {
		if (!candidates[i].size)
			continue;
		if (!ties || candidates[i].size > candidates[best].size) {
			best = i;
			ties = 1;
		} else if (candidates[i].size == candidates[best].size) {
			ties++;
		}
	}
	if (!ties) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len,
				 "SPI-backed MTD devices have no readable size");
		return -1;
	}
	if (ties > 1) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len,
				 "Multiple SPI-backed MTD devices share the largest size (%llu bytes)",
				 (unsigned long long)candidates[best].size);
		return -1;
	}

	*selected = best;
	return 0;
}

int ela_spi_parse_device_index(const char *text, size_t *index,
			       char *errbuf, size_t errbuf_len)
{
	char *end;
	unsigned long long value;

	if (!text || !*text || !index || text[0] < '0' || text[0] > '9') {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Invalid SPI device index");
		return -1;
	}
	errno = 0;
	value = strtoull(text, &end, 10);
	if (errno || end == text || *end || value > UINT32_MAX) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len,
				 "Invalid SPI device index: %s", text);
		return -1;
	}
	*index = (size_t)value;
	return 0;
}
