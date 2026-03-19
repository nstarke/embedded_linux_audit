// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef NET_WS_URL_UTIL_H
#define NET_WS_URL_UTIL_H

#include <stddef.h>
#include <stdint.h>

void ela_ws_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_sz);
int ela_ws_parse_url(const char *url,
		     char *host, size_t host_sz,
		     uint16_t *port_out,
		     char *path, size_t path_sz,
		     int *is_tls_out);
int ela_ws_build_terminal_url(const char *base_url, const char *mac, char *out, size_t out_sz);
int ela_ws_build_handshake_request(char *out,
				   size_t out_sz,
				   const char *host,
				   uint16_t port,
				   const char *path,
				   int is_tls,
				   const char *auth_token,
				   const char *websocket_key);
int ela_is_ws_url(const char *url);

#endif
