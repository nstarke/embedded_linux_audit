// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tcp_runtime_util.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

bool ela_tcp_is_loopback_ipv4(const char *ip)
{
	return ip && !strncmp(ip, "127.", 4);
}

bool ela_tcp_should_skip_nameserver(const char *ip)
{
	return !ip || !*ip || ela_tcp_is_loopback_ipv4(ip);
}

int ela_tcp_parse_nameserver_line(const char *line, char *out, size_t out_sz)
{
	const char *p;
	size_t len = 0;

	if (!line || !out || out_sz == 0)
		return -1;

	p = line;
	while (*p == ' ' || *p == '\t')
		p++;
	if (strncmp(p, "nameserver", 10) != 0)
		return -1;
	p += 10;
	while (*p == ' ' || *p == '\t')
		p++;
	if (!*p || *p == '#' || *p == '\n' || *p == '\r')
		return -1;

	while (*p && *p != '\n' && *p != '\r' && *p != ' ' && *p != '\t' && *p != '#') {
		if (len + 1 >= out_sz)
			return -1;
		out[len++] = *p++;
	}
	out[len] = '\0';
	return len > 0 ? 0 : -1;
}

int ela_tcp_parse_default_gateway_line(const char *line, char *buf, size_t buf_sz)
{
	char iface[64];
	unsigned int dest, gw, flags, mask;
	unsigned int ref, use, metric, mtu, win, irtt;
	struct in_addr addr;
	int n;

	if (!line || !buf || buf_sz == 0)
		return -1;

	n = sscanf(line, "%63s %X %X %X %u %u %u %X %u %u %u",
		   iface, &dest, &gw, &flags,
		   &ref, &use, &metric, &mask,
		   &mtu, &win, &irtt);
	if (n < 8)
		return -1;
	if (dest != 0 || !(flags & 0x0002) || gw == 0)
		return -1;

	addr.s_addr = gw;
	return inet_ntop(AF_INET, &addr, buf, (socklen_t)buf_sz) ? 0 : -1;
}

bool ela_tcp_should_try_udp_resolve_fallback(int getaddrinfo_rc, const char *host)
{
	struct in_addr addr;

	if (getaddrinfo_rc == 0 || !host || !*host)
		return false;
	return inet_pton(AF_INET, host, &addr) != 1;
}

int ela_tcp_has_nameserver_in_file(FILE *f)
{
	char line[256];
	char ns[16];

	if (!f)
		return 0;
	while (fgets(line, (int)sizeof(line), f)) {
		if (ela_tcp_parse_nameserver_line(line, ns, sizeof(ns)) == 0)
			return 1;
	}
	return 0;
}

int ela_tcp_read_nameservers_from_file(FILE *f, char ns[][16], int max_ns)
{
	char line[256];
	int count = 0;

	if (!f || !ns || max_ns <= 0)
		return 0;
	while (count < max_ns && fgets(line, (int)sizeof(line), f)) {
		if (ela_tcp_parse_nameserver_line(line, ns[count], sizeof(ns[count])) == 0)
			count++;
	}
	return count;
}

int ela_tcp_get_gateway_from_route_file(FILE *f, char *buf, size_t buf_sz)
{
	char line[256];

	if (!f || !buf || buf_sz == 0)
		return -1;
	/* skip header */
	if (!fgets(line, (int)sizeof(line), f))
		return -1;
	while (fgets(line, (int)sizeof(line), f)) {
		if (ela_tcp_parse_default_gateway_line(line, buf, buf_sz) == 0)
			return 0;
	}
	return -1;
}
