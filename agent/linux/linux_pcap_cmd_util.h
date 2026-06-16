// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef AGENT_LINUX_LINUX_PCAP_CMD_UTIL_H
#define AGENT_LINUX_LINUX_PCAP_CMD_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#define ELA_PCAP_MAGIC_USEC 0xa1b2c3d4U
#define ELA_PCAP_VERSION_MAJOR 2U
#define ELA_PCAP_VERSION_MINOR 4U

struct ela_pcap_file_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
};

struct ela_pcap_record_header {
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t caplen;
	uint32_t len;
};

int ela_pcap_make_global_header(int linktype, int snaplen,
				struct ela_pcap_file_header *out);
int ela_pcap_make_record_header(const struct timeval *ts,
				uint32_t caplen,
				uint32_t len,
				struct ela_pcap_record_header *out);
int ela_pcap_build_ws_url(const char *http_uri,
			  const char *mac,
			  char *out,
			  size_t out_sz);

#endif
