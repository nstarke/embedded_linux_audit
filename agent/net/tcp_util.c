// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tcp_util.h"
#include "tcp_parse_util.h"
#include "tcp_runtime_util.h"
#include "../embedded_linux_audit_cmd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * DNS auto-configuration: if /etc/resolv.conf has no nameservers, use the
 * default gateway from /proc/net/route as a fallback.
 * ---------------------------------------------------------------------- */

#ifdef __linux__

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */
static int ela_has_dns_configured(void)
{
	FILE *f;
	int rc;

	f = fopen("/etc/resolv.conf", "r");
	if (!f)
		return 0;
	rc = ela_tcp_has_nameserver_in_file(f);
	fclose(f);
	return rc;
}

/* Read /proc/net/route; return the default gateway as a dotted string.
 * Returns 0 on success, -1 if not found. */
static int ela_get_default_gateway(char *buf, size_t buf_sz)
{
	FILE *f;
	int rc;

	f = fopen("/proc/net/route", "r");
	if (!f)
		return -1;
	rc = ela_tcp_get_gateway_from_route_file(f, buf, buf_sz);
	fclose(f);
	return rc;
}

static int ela_read_nameservers(char ns[][16], int max_ns)
{
	FILE *f;
	int count;

	f = fopen("/etc/resolv.conf", "r");
	if (!f)
		return 0;
	count = ela_tcp_read_nameservers_from_file(f, ns, max_ns);
	fclose(f);
	return count;
}

static int ela_dns_query_a(const char *ns_ip, const char *hostname,
			   char *ip_buf, size_t ip_buf_len)
{
	uint8_t pkt[512];
	uint8_t resp[512];
	struct sockaddr_in ns_addr;
	struct timeval tv;
	int sock;
	int pkt_len;
	ssize_t n;

	pkt_len = ela_dns_build_query_packet(hostname, pkt, (int)sizeof(pkt));
	if (pkt_len < 0)
		return -1;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;

	tv.tv_sec = 2;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	memset(&ns_addr, 0, sizeof(ns_addr));
	ns_addr.sin_family = AF_INET;
	ns_addr.sin_port = htons(53);
	if (inet_pton(AF_INET, ns_ip, &ns_addr.sin_addr) != 1) {
		close(sock);
		return -1;
	}

	if (sendto(sock, pkt, (size_t)pkt_len, 0,
		   (struct sockaddr *)&ns_addr, sizeof(ns_addr)) != pkt_len) {
		close(sock);
		return -1;
	}

	n = recv(sock, resp, sizeof(resp), 0);
	close(sock);
	if (n < 12)
		return -1;

	if (!(resp[2] & 0x80) || (resp[3] & 0x0f) != 0)
		return -1;

	return ela_dns_extract_first_a_record(resp, (size_t)n, ip_buf, ip_buf_len);
}

static int ela_udp_resolve_ipv4(const char *hostname, char *ip_buf, size_t ip_buf_len)
{
	char ns[3][16];
	char gw[INET_ADDRSTRLEN];
	int ns_count;
	int i;

	ns_count = ela_read_nameservers(ns, 3);
	for (i = 0; i < ns_count; i++) {
		if (ela_tcp_should_skip_nameserver(ns[i]))
			continue;
		if (ela_dns_query_a(ns[i], hostname, ip_buf, ip_buf_len) == 0)
			return 0;
	}

	if (ela_get_default_gateway(gw, sizeof(gw)) == 0 &&
	    !ela_tcp_should_skip_nameserver(gw) &&
	    ela_dns_query_a(gw, hostname, ip_buf, ip_buf_len) == 0) {
		return 0;
	}

	return -1;
}

/* Write gateway as nameserver to /etc/resolv.conf if none is configured. */
void ela_ensure_dns_configured(void)
{
	char  gw[INET_ADDRSTRLEN];
	FILE *f;

	if (ela_has_dns_configured())
		return;
	if (ela_get_default_gateway(gw, sizeof(gw)) != 0)
		return;

	f = fopen("/etc/resolv.conf", "w");
	if (!f)
		return;
	fprintf(f, "nameserver %s\n", gw);
	fclose(f);
}
#endif /* __linux__ */

#ifndef __linux__
void ela_ensure_dns_configured(void)
{
}
#endif

int connect_tcp_host_port(const char *host, uint16_t port)
{
	struct in_addr addr;
	struct sockaddr_in sa;
	int sock = -1;

	if (!host || !*host || !port)
		return -1;

	if (inet_pton(AF_INET, host, &addr) != 1)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr = addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

int connect_tcp_host_port_any(const char *host, uint16_t port)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	char portbuf[8];
	int sock = -1;
	int rc;
#ifdef __linux__
	static int dns_ensured;
	if (!dns_ensured) {
		ela_ensure_dns_configured();
		dns_ensured = 1;
	}
#endif

	if (!host || !*host || !port)
		return -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(portbuf, sizeof(portbuf), "%u", (unsigned int)port);
	rc = getaddrinfo(host, portbuf, &hints, &res);
	if (rc != 0 || !res) {
#ifdef __linux__
		char ip[INET_ADDRSTRLEN];

		if (ela_tcp_should_try_udp_resolve_fallback(rc, host) &&
		    ela_udp_resolve_ipv4(host, ip, sizeof(ip)) == 0)
			return connect_tcp_host_port(ip, port);
#endif
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0)
			continue;
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(sock);
		sock = -1;
	}

	freeaddrinfo(res);
	return sock;
}

int ela_connect_tcp_any(const char *spec)
{
	char host[256];
	uint16_t port;

	if (!spec || !*spec)
		return -1;

	if (ela_parse_tcp_target(spec, host, sizeof(host), &port) != 0)
		return -1;

	return connect_tcp_host_port_any(host, port);
}

int ela_connect_tcp_ipv4(const char *spec)
{
	char host[64];
	uint16_t port;
	int sock;
	struct sockaddr_in sa;

	if (!spec || !*spec)
		return -1;

	if (ela_parse_tcp_target(spec, host, sizeof(host), &port) != 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &sa.sin_addr) != 1)
		return -1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

bool ela_is_valid_tcp_output_target(const char *spec)
{
	return ela_is_valid_ipv4_tcp_target(spec);
}

int ela_send_all(int sock, const uint8_t *buf, size_t len)
{
	while (len) {
		ssize_t n = send(sock, buf, len, 0);
		if (n <= 0)
			return -1;
		buf += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

/* LCOV_EXCL_STOP */
