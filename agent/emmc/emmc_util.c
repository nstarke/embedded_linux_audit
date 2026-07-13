// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "emmc_util.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int ela_emmc_select_dump_candidate(const struct ela_emmc_candidate *candidates,
				   size_t count, size_t *selected,
				   char *errbuf, size_t errbuf_sz)
{
	uint64_t largest = 0;
	size_t largest_index = 0;
	size_t largest_count = 0;
	size_t i;

	if (!candidates || !selected) {
		if (errbuf && errbuf_sz)
			snprintf(errbuf, errbuf_sz, "Invalid eMMC candidate list");
		return -1;
	}
	for (i = 0; i < count; i++) {
		if (!candidates[i].size)
			continue;
		if (candidates[i].size > largest) {
			largest = candidates[i].size;
			largest_index = i;
			largest_count = 1;
		} else if (candidates[i].size == largest) {
			largest_count++;
		}
	}
	if (!largest) {
		if (errbuf && errbuf_sz)
			snprintf(errbuf, errbuf_sz, "No readable eMMC devices found");
		return -1;
	}
	if (largest_count != 1) {
		if (errbuf && errbuf_sz)
			snprintf(errbuf, errbuf_sz,
				 "Multiple largest eMMC devices found; specify an index");
		return -1;
	}
	*selected = largest_index;
	return 0;
}

int ela_emmc_parse_device_index(const char *text, size_t *index,
				char *errbuf, size_t errbuf_sz)
{
	unsigned long long value;
	char *end = NULL;

	if (!text || !*text || text[0] == '-' || text[0] == '+')
		goto invalid;
	errno = 0;
	value = strtoull(text, &end, 10);
	if (errno || !end || *end || value > UINT32_MAX || value > SIZE_MAX)
		goto invalid;
	*index = (size_t)value;
	return 0;

invalid:
	if (errbuf && errbuf_sz)
		snprintf(errbuf, errbuf_sz, "Invalid eMMC device index");
	return -1;
}
