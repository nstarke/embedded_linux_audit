// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tcp_parse_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ela_parse_tcp_target(const char *spec, char *host, size_t host_sz, uint16_t *port_out)
{
	char local[256];
	char *colon;
	char *end;
	unsigned long port_ul;

	if (!spec || !*spec || !host || host_sz == 0 || !port_out)
		return -1;

	strncpy(local, spec, sizeof(local) - 1);
	local[sizeof(local) - 1] = '\0';
	colon = strrchr(local, ':');
	if (!colon || colon == local || *(colon + 1) == '\0')
		return -1;

	*colon = '\0';
	errno = 0;
	port_ul = strtoul(colon + 1, &end, 10);
	if (errno || !end || *end || port_ul == 0 || port_ul > 65535)
		return -1;
	if (snprintf(host, host_sz, "%s", local) >= (int)host_sz)
		return -1;

	*port_out = (uint16_t)port_ul;
	return 0;
}

bool ela_is_valid_ipv4_tcp_target(const char *spec)
{
	char host[64];
	uint16_t port;
	struct in_addr addr;

	if (ela_parse_tcp_target(spec, host, sizeof(host), &port) != 0)
		return false;
	(void)port;
	return inet_pton(AF_INET, host, &addr) == 1;
}

int ela_dns_build_query_packet(const char *hostname, uint8_t *buf, int buf_len)
{
	int pos = 12;
	const char *p = hostname;

	if (!hostname || !buf || buf_len < 32)
		return -1;

	memset(buf, 0, 12);
	buf[0] = 0xab; buf[1] = 0xcd;
	buf[2] = 0x01; buf[3] = 0x00;
	buf[4] = 0x00; buf[5] = 0x01;

	while (*p) {
		const char *dot = strchr(p, '.');
		int label_len = dot ? (int)(dot - p) : (int)strlen(p);

		if (label_len <= 0 || label_len > 63 || pos + 1 + label_len + 4 > buf_len)
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
	buf[pos++] = 0x00; buf[pos++] = 0x01;
	buf[pos++] = 0x00; buf[pos++] = 0x01;
	return pos;
}

int ela_dns_extract_first_a_record(const uint8_t *resp, size_t resp_len, char *ip_buf, size_t ip_buf_len)
{
	int pos;
	int qdcount;
	int ancount;
	int i;

	if (!resp || resp_len < 12 || !ip_buf || ip_buf_len == 0)
		return -1;
	if (!(resp[2] & 0x80) || (resp[3] & 0x0f) != 0)
		return -1;

	qdcount = (resp[4] << 8) | resp[5];
	ancount = (resp[6] << 8) | resp[7];
	if (ancount <= 0)
		return -1;
	if (ancount > 256)
		ancount = 256; /* cap tainted network value */

	pos = 12;
	for (i = 0; i < qdcount && pos < (int)resp_len; i++) {
		while (pos < (int)resp_len) {
			if (resp[pos] == 0) { pos++; break; }
			if ((resp[pos] & 0xC0) == 0xC0) { pos += 2; break; }
			pos += resp[pos] + 1;
		}
		pos += 4;
	}

	for (i = 0; i < ancount && pos < (int)resp_len; i++) {
		int rtype, rdlen;

		if ((resp[pos] & 0xC0) == 0xC0) {
			pos += 2;
		} else {
			while (pos < (int)resp_len) {
				if (resp[pos] == 0) { pos++; break; }
				if ((resp[pos] & 0xC0) == 0xC0) { pos += 2; break; }
				pos += resp[pos] + 1;
			}
		}
		if (pos + 10 > (int)resp_len)
			break;
		rtype = (resp[pos] << 8) | resp[pos + 1];
		rdlen = (resp[pos + 8] << 8) | resp[pos + 9];
		pos += 10;

		if (rtype == 1 && rdlen == 4 && pos + 4 <= (int)resp_len) {
			snprintf(ip_buf, ip_buf_len, "%d.%d.%d.%d",
				 resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]);
			return 0;
		}
		pos += rdlen;
	}

	return -1;
}
