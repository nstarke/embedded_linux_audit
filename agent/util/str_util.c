// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "str_util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int append_text(char **buf, size_t *len, size_t *cap, const char *text)
{
	if (!text)
		return -1;
	return append_bytes(buf, len, cap, text, strlen(text));
}

int append_bytes(char **buf, size_t *len, size_t *cap, const char *data, size_t data_len)
{
	char *tmp;
	size_t need;
	size_t new_cap;

	if (!buf || !len || !cap || (!data && data_len))
		return -1;

	need = *len + data_len + 1;
	if (need > *cap) {
		new_cap = *cap ? *cap : 256;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(*buf, new_cap);
		if (!tmp)
			return -1;
		*buf = tmp;
		*cap = new_cap;
	}

	if (data_len)
		memcpy(*buf + *len, data, data_len);
	*len += data_len;
	(*buf)[*len] = '\0';
	return 0;
}

char *url_percent_encode(const char *text)
{
	static const char hex[] = "0123456789ABCDEF";
	char *out = NULL;
	size_t len = 0;
	size_t cap = 0;
	const unsigned char *p = (const unsigned char *)text;

	if (!text)
		return NULL;

	while (*p) {
		if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
			if (append_bytes(&out, &len, &cap, (const char *)p, 1) != 0)
				goto fail;
		} else {
			char esc[3];
			esc[0] = '%';
			esc[1] = hex[*p >> 4];
			esc[2] = hex[*p & 0x0F];
			if (append_bytes(&out, &len, &cap, esc, sizeof(esc)) != 0)
				goto fail;
		}
		p++;
	}

	return out;

fail:
	free(out);
	return NULL;
}

int ela_json_append_escaped(char *out, size_t out_len, size_t *pos, const char *value)
{
	size_t i;

	if (!out || !out_len || !pos || !value)
		return -1;

	for (i = 0; value[i]; i++) {
		unsigned char c = (unsigned char)value[i];
		const char *esc = NULL;
		char hex[7];
		size_t need;

		if (c == '"')
			esc = "\\\"";
		else if (c == '\\')
			esc = "\\\\";
		else if (c == '\n')
			esc = "\\n";
		else if (c == '\r')
			esc = "\\r";
		else if (c == '\t')
			esc = "\\t";

		if (esc) {
			need = strlen(esc);
			if (*pos + need >= out_len)
				return -1;
			memcpy(out + *pos, esc, need);
			*pos += need;
			continue;
		}

		if (c < 0x20) {
			snprintf(hex, sizeof(hex), "\\u%04x", c);
			need = strlen(hex);
			if (*pos + need >= out_len)
				return -1;
			memcpy(out + *pos, hex, need);
			*pos += need;
			continue;
		}

		if (*pos + 1U >= out_len)
			return -1;
		out[*pos] = (char)c;
		(*pos)++;
	}
	out[*pos] = '\0';
	return 0;
}
