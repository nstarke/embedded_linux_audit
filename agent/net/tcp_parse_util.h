// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef NET_TCP_PARSE_UTIL_H
#define NET_TCP_PARSE_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int ela_parse_tcp_target(const char *spec, char *host, size_t host_sz, uint16_t *port_out);
bool ela_is_valid_ipv4_tcp_target(const char *spec);
int ela_dns_build_query_packet(const char *hostname, uint8_t *buf, int buf_len);
int ela_dns_extract_first_a_record(const uint8_t *resp, size_t resp_len, char *ip_buf, size_t ip_buf_len);

#endif
