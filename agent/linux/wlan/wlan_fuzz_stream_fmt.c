// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "wlan_fuzz_stream_fmt.h"

#include <string.h>

int wlan_fuzz_format_case_line(char *out, size_t outsz, const char *msg_name,
			       const uint8_t *payload, int len, const char *note)
{
	static const char hex[] = "0123456789abcdef";
	size_t off = 0;
	size_t nlen;
	int i;

	if (!out || outsz == 0 || !msg_name || len < 0 || (len > 0 && !payload))
		return -1;

	nlen = strlen(msg_name);
	if (nlen + 2 >= outsz)		/* name + ' ' + at least a NUL */
		return -1;
	memcpy(out + off, msg_name, nlen);
	off += nlen;
	out[off++] = ' ';

	for (i = 0; i < len; i++) {
		if (off + 2 >= outsz)	/* stop cleanly if the buffer fills */
			break;
		out[off++] = hex[(payload[i] >> 4) & 0xF];
		out[off++] = hex[payload[i] & 0xF];
	}

	if (note && *note && off + 2 < outsz) {
		out[off++] = ' ';
		out[off++] = '#';
		for (; *note && off + 1 < outsz; note++) {
			/* keep it single-line; the crash-file grammar is line-based */
			out[off++] = (*note == '\n' || *note == '\r') ? ' ' : *note;
		}
	}

	out[off] = '\0';
	return (int)off;
}
