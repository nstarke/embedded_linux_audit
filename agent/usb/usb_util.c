// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "usb_util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int ela_usb_parse_u32(const char *text, uint32_t *value,
		      const char *label, char *errbuf, size_t errbuf_sz)
{
	unsigned long long parsed;
	char *end = NULL;

	if (!text || !*text || !value || text[0] == '-' || text[0] == '+')
		goto invalid;
	errno = 0;
	parsed = strtoull(text, &end, 10);
	if (errno || !end || *end || parsed > UINT32_MAX)
		goto invalid;
	*value = (uint32_t)parsed;
	return 0;

invalid:
	if (errbuf && errbuf_sz)
		snprintf(errbuf, errbuf_sz, "Invalid %s", label ? label : "value");
	return -1;
}

int ela_usb_select_descriptor_candidate(const struct ela_usb_candidate *items,
					size_t count, size_t *selected,
					char *errbuf, size_t errbuf_sz)
{
	size_t found = 0;
	size_t found_index = 0;
	size_t i;

	if (!items || !selected)
		goto invalid;
	for (i = 0; i < count; i++) {
		if (!items[i].parent_devnum)
			continue;
		found++;
		found_index = i;
	}
	if (found == 1) {
		*selected = found_index;
		return 0;
	}
	if (errbuf && errbuf_sz) {
		if (!found)
			snprintf(errbuf, errbuf_sz, "No non-root USB devices found");
		else
			snprintf(errbuf, errbuf_sz,
				 "Multiple USB devices found; specify an index");
	}
	return -1;

invalid:
	if (errbuf && errbuf_sz)
		snprintf(errbuf, errbuf_sz, "Invalid USB device list");
	return -1;
}
