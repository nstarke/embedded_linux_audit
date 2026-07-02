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
 * Build GDB tunnel URLs from a base URL, a hex session key, and the device MAC.
 *
 * Trailing slashes are stripped from base_url before appending the paths.
 * On success, in_url receives "<base>/gdb/in/<key>?mac=<mac>" and out_url
 * receives "<base>/gdb/out/<key>". The MAC is attached to the agent (in) side
 * only so the bridge can record which device the session belongs to and gate
 * the operator (out) side to users associated with that device. If mac is NULL
 * or empty the in URL omits the query string.
 *
 * Returns 0 on success, -1 if either URL would be truncated.
 */
int ela_gdb_tunnel_build_urls(const char *base_url, const char *hex_key,
			      const char *mac,
			      char *in_url,  size_t in_sz,
			      char *out_url, size_t out_sz);

/*
 * Return 1 if key is exactly 32 lowercase hexadecimal characters, 0 otherwise.
 */
int ela_gdb_tunnel_key_is_valid(const char *key);

/*
 * Resolve the tunnel's base URL (and TLS-verification setting) from the parsed
 * command line and the saved agent conf.
 *
 * - arg_url: the <WSS_BASE_URL> argument, or NULL/"" when omitted.
 * - conf_remote: the terminal-API server saved in the conf (`remote`), or
 *   NULL/"" when the agent never phoned home.
 * - conf_insecure: the conf's insecure flag (0/1).
 * - insecure_explicit: non-zero when --insecure was passed on the command line.
 * - *in_out_insecure: the current insecure flag (from --insecure); on success,
 *   when the URL is defaulted from the conf and --insecure was not explicit, it
 *   is raised to conf_insecure.
 *
 * On success writes the chosen base URL to *out_base_url (pointing into arg_url
 * or conf_remote — no copy) and returns 0. Returns -1 when no URL was given and
 * none is configured, or on a NULL out pointer.
 */
int ela_gdb_tunnel_resolve_target(const char *arg_url,
				   const char *conf_remote,
				   int conf_insecure,
				   int insecure_explicit,
				   const char **out_base_url,
				   int *in_out_insecure);

#endif /* LINUX_GDBSERVER_TUNNEL_UTIL_H */
