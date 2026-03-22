// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_gdbserver_tunnel_util.h"

#include <stdio.h>
#include <string.h>

void ela_gdb_tunnel_format_hex_key(const uint8_t *raw, size_t raw_len,
				   char *out)
{
	size_t i;

	for (i = 0; i < raw_len; i++)
		snprintf(out + i * 2U, 3, "%02x", (unsigned int)raw[i]);
	out[raw_len * 2U] = '\0';
}

int ela_gdb_tunnel_build_urls(const char *base_url, const char *hex_key,
			      char *in_url,  size_t in_sz,
			      char *out_url, size_t out_sz)
{
	size_t base_len;
	int    n;

	base_len = strlen(base_url);
	while (base_len > 0 && base_url[base_len - 1] == '/')
		base_len--;

	n = snprintf(in_url, in_sz, "%.*s/gdb/in/%s",
		     (int)base_len, base_url, hex_key);
	if (n < 0 || (size_t)n >= in_sz)
		return -1;

	n = snprintf(out_url, out_sz, "%.*s/gdb/out/%s",
		     (int)base_len, base_url, hex_key);
	if (n < 0 || (size_t)n >= out_sz)
		return -1;

	return 0;
}

int ela_gdb_tunnel_key_is_valid(const char *key)
{
	size_t i;
	char   c;

	if (!key)
		return 0;
	for (i = 0; i < 32; i++) {
		c = key[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
			return 0;
	}
	return key[32] == '\0';
}
