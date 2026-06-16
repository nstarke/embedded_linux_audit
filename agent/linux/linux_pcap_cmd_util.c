// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_pcap_cmd_util.h"

#include <stdio.h>
#include <string.h>

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
