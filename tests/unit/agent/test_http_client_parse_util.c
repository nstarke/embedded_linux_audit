// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/http_client_parse_util.h"

#include <string.h>

static void test_http_client_parse_url_authority_and_resolve_entry(void)
{
	char host[256];
	char port[8];
	char entry[288];

	ELA_ASSERT_INT_EQ(0, ela_http_parse_url_authority("https://ela.example:8443/upload", host, sizeof(host), port, sizeof(port)));
	ELA_ASSERT_STR_EQ("ela.example", host);
	ELA_ASSERT_STR_EQ("8443", port);
	ELA_ASSERT_INT_EQ(0, ela_http_build_resolve_entry("https://ela.example:8443/upload", "1.2.3.4", entry, sizeof(entry)));
	ELA_ASSERT_STR_EQ("ela.example:8443:1.2.3.4", entry);
}

static void test_http_client_dns_query_packet_builder_encodes_labels(void)
{
	uint8_t pkt[128];
	int len;

	len = ela_http_build_dns_query_packet("ela.example", pkt, (int)sizeof(pkt));
	ELA_ASSERT_TRUE(len > 20);
	ELA_ASSERT_INT_EQ(0xab, pkt[0]);
	ELA_ASSERT_INT_EQ(3, pkt[12]);
	ELA_ASSERT_TRUE(memmem(pkt, (size_t)len, "ela", 3) != NULL);
}

int run_http_client_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "http_client_parse_url_authority_and_resolve_entry", test_http_client_parse_url_authority_and_resolve_entry },
		{ "http_client_dns_query_packet_builder_encodes_labels", test_http_client_dns_query_packet_builder_encodes_labels },
	};

	return ela_run_test_suite("http_client_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
