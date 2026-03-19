// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef NET_TCP_RUNTIME_UTIL_H
#define NET_TCP_RUNTIME_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

bool ela_tcp_is_loopback_ipv4(const char *ip);
bool ela_tcp_should_skip_nameserver(const char *ip);
int ela_tcp_parse_nameserver_line(const char *line, char *out, size_t out_sz);
int ela_tcp_parse_default_gateway_line(const char *line, char *buf, size_t buf_sz);
bool ela_tcp_should_try_udp_resolve_fallback(int getaddrinfo_rc, const char *host);

/*
 * Returns 1 if f contains at least one valid "nameserver" line, 0 otherwise.
 */
int ela_tcp_has_nameserver_in_file(FILE *f);

/*
 * Parse up to max_ns nameserver addresses from an open resolv.conf FILE*.
 * Returns the count of nameservers stored in ns[][16].
 */
int ela_tcp_read_nameservers_from_file(FILE *f, char ns[][16], int max_ns);

/*
 * Parse a /proc/net/route-formatted FILE* and fill buf with the default
 * gateway in dotted-decimal form.  Returns 0 on success, -1 if not found.
 */
int ela_tcp_get_gateway_from_route_file(FILE *f, char *buf, size_t buf_sz);

#endif
