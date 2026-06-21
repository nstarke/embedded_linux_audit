// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_pcap_cmd_util.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint16_t pcap_read_u16(const uint8_t *p, int swap)
{
	uint16_t v;

	memcpy(&v, p, sizeof(v));
	if (swap)
		v = (uint16_t)((v >> 8) | (v << 8));
	return v;
}

static uint32_t pcap_read_u32(const uint8_t *p, int swap)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));
	if (swap)
		v = ((v & 0x000000ffU) << 24) | ((v & 0x0000ff00U) << 8) |
		    ((v & 0x00ff0000U) >> 8) | ((v & 0xff000000U) >> 24);
	return v;
}

int ela_pcap_make_global_header(int linktype, int snaplen,
				struct ela_pcap_file_header *out)
{
	if (!out || linktype < 0 || snaplen <= 0)
		return -1;

	memset(out, 0, sizeof(*out));
	out->magic = ELA_PCAP_MAGIC_USEC;
	out->version_major = ELA_PCAP_VERSION_MAJOR;
	out->version_minor = ELA_PCAP_VERSION_MINOR;
	out->snaplen = (uint32_t)snaplen;
	out->linktype = (uint32_t)linktype;
	return 0;
}

int ela_pcap_make_record_header(const struct timeval *ts,
				uint32_t caplen,
				uint32_t len,
				struct ela_pcap_record_header *out)
{
	if (!ts || !out || caplen > len)
		return -1;

	memset(out, 0, sizeof(*out));
	out->ts_sec = (uint32_t)ts->tv_sec;
	out->ts_usec = (uint32_t)ts->tv_usec;
	out->caplen = caplen;
	out->len = len;
	return 0;
}

int ela_pcap_build_ws_url(const char *http_uri,
			  const char *mac,
			  char *out,
			  size_t out_sz)
{
	const char *scheme;
	const char *authority;
	const char *authority_end;
	size_t authority_len;
	int n;

	if (!http_uri || !*http_uri || !mac || !*mac || !out || out_sz == 0)
		return -1;

	if (!strncmp(http_uri, "http://", 7)) {
		scheme = "ws://";
		authority = http_uri + 7;
	} else if (!strncmp(http_uri, "https://", 8)) {
		scheme = "wss://";
		authority = http_uri + 8;
	} else {
		return -1;
	}

	authority_end = authority;
	while (*authority_end && *authority_end != '/' &&
	       *authority_end != '?' && *authority_end != '#')
		authority_end++;
	authority_len = (size_t)(authority_end - authority);
	if (!authority_len)
		return -1;

	n = snprintf(out, out_sz, "%s%.*s/pcap/%s",
		     scheme, (int)authority_len, authority, mac);
	return (n > 0 && (size_t)n < out_sz) ? 0 : -1;
}

int ela_pcap_parse_global_header(const void *buf, size_t len,
				 struct ela_pcap_file_header *out,
				 int *needs_swap)
{
	const uint8_t *p = (const uint8_t *)buf;
	uint32_t magic;
	int swap;

	if (!buf || !out || !needs_swap ||
	    len < sizeof(struct ela_pcap_file_header))
		return -1;

	memcpy(&magic, p, sizeof(magic));
	if (magic == ELA_PCAP_MAGIC_USEC || magic == ELA_PCAP_MAGIC_NSEC)
		swap = 0;
	else if (magic == ELA_PCAP_MAGIC_USEC_SWAPPED ||
		 magic == ELA_PCAP_MAGIC_NSEC_SWAPPED)
		swap = 1;
	else
		return -1;

	memset(out, 0, sizeof(*out));
	out->magic = magic;
	out->version_major = pcap_read_u16(p + 4, swap);
	out->version_minor = pcap_read_u16(p + 6, swap);
	out->thiszone = (int32_t)pcap_read_u32(p + 8, swap);
	out->sigfigs = pcap_read_u32(p + 12, swap);
	out->snaplen = pcap_read_u32(p + 16, swap);
	out->linktype = pcap_read_u32(p + 20, swap);
	*needs_swap = swap;
	return 0;
}

int ela_pcap_parse_record_header(const void *buf, size_t len, int needs_swap,
				 struct ela_pcap_record_header *out)
{
	const uint8_t *p = (const uint8_t *)buf;

	if (!buf || !out || len < sizeof(struct ela_pcap_record_header))
		return -1;

	memset(out, 0, sizeof(*out));
	out->ts_sec = pcap_read_u32(p, needs_swap);
	out->ts_usec = pcap_read_u32(p + 4, needs_swap);
	out->caplen = pcap_read_u32(p + 8, needs_swap);
	out->len = pcap_read_u32(p + 12, needs_swap);
	if (out->caplen > out->len)
		return -1;
	return 0;
}
