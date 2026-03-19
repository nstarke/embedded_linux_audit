// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_HTTP_CLIENT_PARSE_UTIL_H
#define ELA_HTTP_CLIENT_PARSE_UTIL_H

#include <stddef.h>
#include <stdint.h>

int ela_http_parse_url_authority(const char *url,
				 char *host,
				 size_t host_sz,
				 char *port_str,
				 size_t port_str_sz);
int ela_http_build_resolve_entry(const char *url,
				 const char *ip,
				 char *entry,
				 size_t entry_sz);
int ela_http_build_dns_query_packet(const char *hostname, uint8_t *buf, int buf_len);

#endif
