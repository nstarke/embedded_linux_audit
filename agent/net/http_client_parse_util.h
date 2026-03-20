// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_HTTP_CLIENT_PARSE_UTIL_H
#define ELA_HTTP_CLIENT_PARSE_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

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

/*
 * Parse the first IPv4 A record from a raw DNS response buffer.
 * Returns 0 on success with ip_buf filled in dotted-decimal, -1 on failure.
 */
int ela_http_parse_dns_a_response(const uint8_t *resp, int resp_len,
				  char *ip_buf, size_t ip_buf_len);

/*
 * Parse nameserver addresses from an open resolv.conf FILE*.
 * Returns the number of nameservers parsed (up to max_ns).
 * Each ns[i] is a NUL-terminated IPv4 string of at most 15 characters.
 */
int ela_http_parse_resolv_conf(FILE *f, char ns[][16], int max_ns);

/*
 * Find the best-matching egress interface for dest_addr_net (network byte
 * order) by parsing a /proc/net/route-formatted FILE*.
 * Returns 0 with ifname_buf filled on success, -1 when no route matches.
 */
int ela_http_parse_route_table(FILE *f, uint32_t dest_addr_net,
			       char *ifname_buf, size_t ifname_buf_len);

#endif
