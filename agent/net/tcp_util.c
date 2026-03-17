// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tcp_util.h"
#include "../embedded_linux_audit_cmd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * DNS auto-configuration: if /etc/resolv.conf has no nameservers, use the
 * default gateway from /proc/net/route as a fallback.
 * ---------------------------------------------------------------------- */

#ifdef __linux__
static int ela_has_dns_configured(void)
{
	FILE *f;
	char  line[256];

	f = fopen("/etc/resolv.conf", "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "nameserver", 10) == 0) {
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

/* Read /proc/net/route; return the default gateway as a dotted string.
 * Returns 0 on success, -1 if not found. */
static int ela_get_default_gateway(char *buf, size_t buf_sz)
{
	FILE        *f;
	char         line[256];
	char         iface[64];
	unsigned int dest, gw, flags, mask;
	struct in_addr addr;
	int          found = 0;

	f = fopen("/proc/net/route", "r");
	if (!f)
		return -1;

	/* skip header */
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		unsigned int ref, use, metric, mtu, win, irtt;
		int n = sscanf(line, "%63s %X %X %X %u %u %u %X %u %u %u",
			       iface, &dest, &gw, &flags,
			       &ref, &use, &metric, &mask,
			       &mtu, &win, &irtt);
		if (n < 8)
			continue;
		/* default route: destination 0.0.0.0, RTF_GATEWAY (0x2) set */
		if (dest == 0 && (flags & 0x0002) && gw != 0) {
			/* /proc/net/route stores in host byte order */
			addr.s_addr = htonl(gw);
			if (inet_ntop(AF_INET, &addr, buf, (socklen_t)buf_sz)) {
				found = 1;
				break;
			}
		}
	}

	fclose(f);
	return found ? 0 : -1;
}

/* Write gateway as nameserver to /etc/resolv.conf if none is configured. */
static void ela_ensure_dns(void)
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
		ela_ensure_dns();
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
	if (rc != 0 || !res)
		return -1;

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
	char *colon;
	char *end;
	unsigned long port_ul;

	if (!spec || !*spec)
		return -1;

	strncpy(host, spec, sizeof(host) - 1);
	host[sizeof(host) - 1] = '\0';
	colon = strrchr(host, ':');
	if (!colon || colon == host || *(colon + 1) == '\0')
		return -1;

	*colon = '\0';
	errno = 0;
	port_ul = strtoul(colon + 1, &end, 10);
	if (errno || *end || port_ul == 0 || port_ul > 65535)
		return -1;

	return connect_tcp_host_port_any(host, (uint16_t)port_ul);
}

int ela_connect_tcp_ipv4(const char *spec)
{
	char host[64];
	char *colon;
	char *end;
	unsigned long port_ul;
	int sock;
	struct sockaddr_in sa;

	if (!spec || !*spec)
		return -1;

	strncpy(host, spec, sizeof(host) - 1);
	host[sizeof(host) - 1] = '\0';
	colon = strrchr(host, ':');
	if (!colon || colon == host || *(colon + 1) == '\0')
		return -1;

	*colon = '\0';
	errno = 0;
	port_ul = strtoul(colon + 1, &end, 10);
	if (errno || *end || port_ul == 0 || port_ul > 65535)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port_ul);
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
	char host[64];
	char *colon;
	char *end;
	unsigned long port_ul;
	struct in_addr addr;

	if (!spec || !*spec)
		return false;

	strncpy(host, spec, sizeof(host) - 1);
	host[sizeof(host) - 1] = '\0';
	colon = strrchr(host, ':');
	if (!colon || colon == host || *(colon + 1) == '\0')
		return false;

	*colon = '\0';
	errno = 0;
	port_ul = strtoul(colon + 1, &end, 10);
	if (errno || *end || port_ul == 0 || port_ul > 65535)
		return false;

	return inet_pton(AF_INET, host, &addr) == 1;
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
