// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_client_parse_util.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <stdbool.h>
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

int ela_http_parse_dns_a_response(const uint8_t *resp, int resp_len,
				  char *ip_buf, size_t ip_buf_len)
{
	int pos, qdcount, ancount, i;

	if (!resp || resp_len < 12 || !ip_buf || ip_buf_len == 0)
		return -1;

	/* Must be a response (QR=1) with RCODE=0 */
	if (!(resp[2] & 0x80) || (resp[3] & 0x0f) != 0)
		return -1;

	qdcount = (resp[4] << 8) | resp[5];
	ancount = (resp[6] << 8) | resp[7];
	if (ancount == 0)
		return -1;

	/* Skip question section */
	pos = 12;
	for (i = 0; i < qdcount && pos < resp_len; i++) {
		while (pos < resp_len) {
			if (resp[pos] == 0)             { pos++; break; }
			if ((resp[pos] & 0xC0) == 0xC0) { pos += 2; break; }
			pos += resp[pos] + 1;
		}
		pos += 4; /* QTYPE + QCLASS */
	}

	/* Parse answer records; return the first A record found */
	for (i = 0; i < ancount && pos < resp_len; i++) {
		int rtype, rdlen;

		if ((resp[pos] & 0xC0) == 0xC0) {
			pos += 2;
		} else {
			while (pos < resp_len) {
				if (resp[pos] == 0)             { pos++; break; }
				if ((resp[pos] & 0xC0) == 0xC0) { pos += 2; break; }
				pos += resp[pos] + 1;
			}
		}

		if (pos + 10 > resp_len)
			break;
		rtype = (resp[pos] << 8) | resp[pos + 1];
		/* skip class (2) + ttl (4) */
		rdlen = (resp[pos + 8] << 8) | resp[pos + 9];
		pos += 10;

		if (rtype == 1 /* A */ && rdlen == 4 && pos + 4 <= resp_len) {
			snprintf(ip_buf, ip_buf_len, "%d.%d.%d.%d",
				 resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]);
			return 0;
		}
		pos += rdlen;
	}
	return -1;
}

int ela_http_parse_resolv_conf(FILE *f, char ns[][16], int max_ns)
{
	char line[256];
	int count = 0;

	if (!f || !ns || max_ns <= 0)
		return 0;

	while (count < max_ns && fgets(line, (int)sizeof(line), f)) {
		const char *p = line;
		int i;

		while (*p == ' ' || *p == '\t') p++;
		if (strncmp(p, "nameserver", 10) != 0)
			continue;
		p += 10;
		while (*p == ' ' || *p == '\t') p++;

		for (i = 0; i < 15 && *p && *p != '\n' && *p != '\r' &&
		            *p != ' ' && *p != '\t' && *p != '#'; i++)
			ns[count][i] = *p++;
		ns[count][i] = '\0';
		if (i > 0)
			count++;
	}
	return count;
}

int ela_http_parse_route_table(FILE *f, uint32_t dest_addr_net,
			       char *ifname_buf, size_t ifname_buf_len)
{
	char line[512];
	uint32_t best_mask = 0;
	uint32_t target_host = ntohl(dest_addr_net);
	bool found = false;

	if (!f || !ifname_buf || ifname_buf_len < IF_NAMESIZE)
		return -1;

	/* Skip header line */
	if (!fgets(line, (int)sizeof(line), f))
		return -1;

	while (fgets(line, (int)sizeof(line), f)) {
		char iface[IF_NAMESIZE];
		unsigned long destination, gateway, flags, refcnt;
		unsigned long use, metric, mask, mtu, window, irtt;
		uint32_t dest_host, mask_host;

		if (sscanf(line, "%15s %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx",
			   iface, &destination, &gateway, &flags, &refcnt, &use,
			   &metric, &mask, &mtu, &window, &irtt) != 11)
			continue;

		if (!(flags & 0x1UL))
			continue;

		dest_host = ntohl((uint32_t)destination);
		mask_host = ntohl((uint32_t)mask);

		if ((target_host & mask_host) != (dest_host & mask_host))
			continue;

		if (!found || mask_host > best_mask) {
			strncpy(ifname_buf, iface, ifname_buf_len - 1);
			ifname_buf[ifname_buf_len - 1] = '\0';
			best_mask = mask_host;
			found = true;
		}
	}
	return found ? 0 : -1;
}
