// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_client_parse_util.h"

#include <stdio.h>
#include <string.h>

int ela_http_parse_url_authority(const char *url,
				 char *host,
				 size_t host_sz,
				 char *port_str,
				 size_t port_str_sz)
{
	const char *authority;
	const char *authority_end;
	const char *port_sep;
	const char *p;
	int host_len;
	int port_len;

	if (!url || !host || !port_str || host_sz == 0 || port_str_sz == 0)
		return -1;

	authority = strstr(url, "://");
	if (!authority)
		return -1;
	authority += 3;

	authority_end = strchr(authority, '/');
	if (!authority_end)
		authority_end = authority + strlen(authority);

	port_sep = NULL;
	for (p = authority; p < authority_end; p++) {
		if (*p == ':')
			port_sep = p;
	}
	if (!port_sep)
		return -1;

	host_len = (int)(port_sep - authority);
	port_len = (int)(authority_end - port_sep - 1);
	if (host_len <= 0 || (size_t)host_len >= host_sz)
		return -1;
	if (port_len <= 0 || (size_t)port_len >= port_str_sz)
		return -1;

	memcpy(host, authority, (size_t)host_len);
	host[host_len] = '\0';
	memcpy(port_str, port_sep + 1, (size_t)port_len);
	port_str[port_len] = '\0';
	return 0;
}

int ela_http_build_resolve_entry(const char *url,
				 const char *ip,
				 char *entry,
				 size_t entry_sz)
{
	char host[256];
	char port[8];

	if (!ip || !*ip || !entry || entry_sz == 0)
		return -1;
	if (ela_http_parse_url_authority(url, host, sizeof(host), port, sizeof(port)) != 0)
		return -1;
	return snprintf(entry, entry_sz, "%s:%s:%s", host, port, ip) >= (int)entry_sz ? -1 : 0;
}

int ela_http_build_dns_query_packet(const char *hostname, uint8_t *buf, int buf_len)
{
	int pos = 12;
	const char *p = hostname;

	if (!hostname || !*hostname || !buf || buf_len < 32)
		return -1;

	memset(buf, 0, 12);
	buf[0] = 0xab;
	buf[1] = 0xcd;
	buf[2] = 0x01;
	buf[3] = 0x00;
	buf[4] = 0x00;
	buf[5] = 0x01;

	while (*p) {
		const char *dot = strchr(p, '.');
		int label_len = dot ? (int)(dot - p) : (int)strlen(p);

		if (label_len <= 0 || label_len > 63)
			return -1;
		if (pos + 1 + label_len + 4 > buf_len)
			return -1;
		buf[pos++] = (uint8_t)label_len;
		memcpy(buf + pos, p, (size_t)label_len);
		pos += label_len;
		if (!dot)
			break;
		p = dot + 1;
	}
	if (pos + 5 > buf_len)
		return -1;
	buf[pos++] = 0;
	buf[pos++] = 0x00;
	buf[pos++] = 0x01;
	buf[pos++] = 0x00;
	buf[pos++] = 0x01;
	return pos;
}
