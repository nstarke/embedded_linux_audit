// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef LINUX_GDBSERVER_TUNNEL_UTIL_H
#define LINUX_GDBSERVER_TUNNEL_UTIL_H

#include <stddef.h>
#include <stdint.h>

/*
 * Format raw_len bytes from raw as a lowercase hex string.
 * out must be at least raw_len * 2 + 1 bytes.
 * Always NUL-terminates out.
 */
void ela_gdb_tunnel_format_hex_key(const uint8_t *raw, size_t raw_len,
				   char *out);

/*
 * Build GDB tunnel URLs from a base URL and a hex session key.
 *
 * Trailing slashes are stripped from base_url before appending the paths.
 * On success, in_url receives "<base>/gdb/in/<key>" and out_url receives
 * "<base>/gdb/out/<key>".
 *
 * Returns 0 on success, -1 if either URL would be truncated.
 */
int ela_gdb_tunnel_build_urls(const char *base_url, const char *hex_key,
			      char *in_url,  size_t in_sz,
			      char *out_url, size_t out_sz);

/*
 * Return 1 if key is exactly 32 lowercase hexadecimal characters, 0 otherwise.
 */
int ela_gdb_tunnel_key_is_valid(const char *key);

#endif /* LINUX_GDBSERVER_TUNNEL_UTIL_H */
