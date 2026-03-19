// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/tcp_parse_util.h"

#include <string.h>

static void test_parse_tcp_target_and_validation(void)
{
	char host[128];
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(0, ela_parse_tcp_target("127.0.0.1:8080", host, sizeof(host), &port));
	ELA_ASSERT_STR_EQ("127.0.0.1", host);
	ELA_ASSERT_INT_EQ(8080, port);
	ELA_ASSERT_TRUE(ela_is_valid_ipv4_tcp_target("127.0.0.1:8080"));
	ELA_ASSERT_FALSE(ela_is_valid_ipv4_tcp_target("localhost:8080"));
}

static void test_dns_query_builder_encodes_qname(void)
{
	uint8_t buf[64];
	int len = ela_dns_build_query_packet("ela.example", buf, sizeof(buf));

	ELA_ASSERT_TRUE(len > 20);
	ELA_ASSERT_INT_EQ(0x03, buf[12]);
	ELA_ASSERT_INT_EQ('e', buf[13]);
	ELA_ASSERT_INT_EQ(0x07, buf[16]);
}

static void test_dns_response_parser_extracts_a_record(void)
{
	const uint8_t resp[] = {
		0xab,0xcd,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,
		0x03,'e','l','a',0x07,'e','x','a','m','p','l','e',0x00,0x00,0x01,0x00,0x01,
		0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3c,0x00,0x04,192,0,2,10
	};
	char ip[32];

	ELA_ASSERT_INT_EQ(0, ela_dns_extract_first_a_record(resp, sizeof(resp), ip, sizeof(ip)));
	ELA_ASSERT_STR_EQ("192.0.2.10", ip);
}

int run_tcp_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "parse_tcp_target_and_validation", test_parse_tcp_target_and_validation },
		{ "dns_query_builder_encodes_qname", test_dns_query_builder_encodes_qname },
		{ "dns_response_parser_extracts_a_record", test_dns_response_parser_extracts_a_record },
	};

	return ela_run_test_suite("tcp_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
