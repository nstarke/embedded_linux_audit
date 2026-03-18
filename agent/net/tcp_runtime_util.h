// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef NET_TCP_RUNTIME_UTIL_H
#define NET_TCP_RUNTIME_UTIL_H

#include <stdbool.h>
#include <stddef.h>

bool ela_tcp_is_loopback_ipv4(const char *ip);
bool ela_tcp_should_skip_nameserver(const char *ip);
int ela_tcp_parse_nameserver_line(const char *line, char *out, size_t out_sz);
int ela_tcp_parse_default_gateway_line(const char *line, char *buf, size_t buf_sz);
bool ela_tcp_should_try_udp_resolve_fallback(int getaddrinfo_rc, const char *host);

#endif
