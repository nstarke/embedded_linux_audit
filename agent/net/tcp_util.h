// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef NET_TCP_UTIL_H
#define NET_TCP_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* Connect to a host (IP or hostname) on the given port. Returns fd or -1. */
int connect_tcp_host_port(const char *host, uint16_t port);

/* Connect using getaddrinfo (supports IPv4 and IPv6). Returns fd or -1. */
int connect_tcp_host_port_any(const char *host, uint16_t port);

/* Ensure /etc/resolv.conf has at least one nameserver when possible. */
void ela_ensure_dns_configured(void);

/* Add a /32 host route for hostname via the non-tunnel gateway (Linux only). */
void ela_ensure_host_route_via_nontunnel(const char *hostname);

#endif /* NET_TCP_UTIL_H */
