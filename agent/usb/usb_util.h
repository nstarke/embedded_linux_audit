// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_USB_UTIL_H
#define ELA_USB_UTIL_H

#include <stddef.h>
#include <stdint.h>

struct ela_usb_candidate {
	uint32_t busnum;
	uint32_t devnum;
	uint32_t parent_devnum;
};

int ela_usb_parse_u32(const char *text, uint32_t *value,
		      const char *label, char *errbuf, size_t errbuf_sz);
int ela_usb_select_descriptor_candidate(const struct ela_usb_candidate *items,
					size_t count, size_t *selected,
					char *errbuf, size_t errbuf_sz);

#endif
