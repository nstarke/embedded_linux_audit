// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/http_client_parse_util.h"

#include <net/if.h>
#include <stdio.h>
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

/* -----------------------------------------------------------------------
 * ela_http_parse_dns_a_response tests
 * ---------------------------------------------------------------------- */

/*
 * Minimal valid response: no question section, one A answer for 192.168.1.1.
 *
 * Header:
 *   ID=0xabcd, QR=1 RCODE=0, QDCOUNT=0, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
 * Answer:
 *   NAME=root(0x00), TYPE=A(1), CLASS=IN(1), TTL=60,
 *   RDLENGTH=4, RDATA=192.168.1.1
 */
static const uint8_t dns_a_simple[] = {
	0xab, 0xcd,              /* ID */
	0x81, 0x80,              /* QR=1, RCODE=0 */
	0x00, 0x00,              /* QDCOUNT=0 */
	0x00, 0x01,              /* ANCOUNT=1 */
	0x00, 0x00, 0x00, 0x00,  /* NSCOUNT, ARCOUNT */
	0x00,                    /* NAME=root */
	0x00, 0x01,              /* TYPE=A */
	0x00, 0x01,              /* CLASS=IN */
	0x00, 0x00, 0x00, 0x3c,  /* TTL=60 */
	0x00, 0x04,              /* RDLENGTH=4 */
	0xc0, 0xa8, 0x01, 0x01,  /* 192.168.1.1 */
};

static void test_dns_a_response_parses_valid_response(void)
{
	char ip[16];

	ELA_ASSERT_INT_EQ(0, ela_http_parse_dns_a_response(
		dns_a_simple, (int)sizeof(dns_a_simple), ip, sizeof(ip)));
	ELA_ASSERT_STR_EQ("192.168.1.1", ip);
}

static void test_dns_a_response_returns_neg1_when_too_short(void)
{
	char ip[16];

	ELA_ASSERT_INT_EQ(-1, ela_http_parse_dns_a_response(
		dns_a_simple, 11, ip, sizeof(ip)));
}

static void test_dns_a_response_returns_neg1_when_not_a_response(void)
{
	/* resp[2] = 0x01: QR bit clear — this is a query, not a response */
	static const uint8_t query_pkt[] = {
		0xab, 0xcd, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		0xc0, 0xa8, 0x01, 0x01,
	};
	char ip[16];

	ELA_ASSERT_INT_EQ(-1, ela_http_parse_dns_a_response(
		query_pkt, (int)sizeof(query_pkt), ip, sizeof(ip)));
}

static void test_dns_a_response_returns_neg1_when_rcode_nonzero(void)
{
	/* resp[3] = 0x83: QR=1, RCODE=3 (NXDOMAIN) */
	static const uint8_t nxdomain[] = {
		0xab, 0xcd, 0x81, 0x83,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	char ip[16];

	ELA_ASSERT_INT_EQ(-1, ela_http_parse_dns_a_response(
		nxdomain, (int)sizeof(nxdomain), ip, sizeof(ip)));
}

static void test_dns_a_response_returns_neg1_when_no_answers(void)
{
	/* Valid response flags but ANCOUNT=0 */
	static const uint8_t empty_answer[] = {
		0xab, 0xcd, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	char ip[16];

	ELA_ASSERT_INT_EQ(-1, ela_http_parse_dns_a_response(
		empty_answer, (int)sizeof(empty_answer), ip, sizeof(ip)));
}

/*
 * Response with a one-label question ("a") followed by a compressed-name
 * answer pointing back to offset 12, A record for 10.0.0.1.
 */
static const uint8_t dns_a_with_question[] = {
	0xab, 0xcd, 0x81, 0x80,
	0x00, 0x01,              /* QDCOUNT=1 */
	0x00, 0x01,              /* ANCOUNT=1 */
	0x00, 0x00, 0x00, 0x00,
	/* Question: "a" */
	0x01, 'a', 0x00,         /* label + root */
	0x00, 0x01, 0x00, 0x01,  /* QTYPE=A, QCLASS=IN */
	/* Answer: compressed name ptr -> offset 12 */
	0xc0, 0x0c,
	0x00, 0x01, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x3c,
	0x00, 0x04,
	0x0a, 0x00, 0x00, 0x01,  /* 10.0.0.1 */
};

static void test_dns_a_response_parses_with_question_section(void)
{
	char ip[16];

	ELA_ASSERT_INT_EQ(0, ela_http_parse_dns_a_response(
		dns_a_with_question, (int)sizeof(dns_a_with_question),
		ip, sizeof(ip)));
	ELA_ASSERT_STR_EQ("10.0.0.1", ip);
}

static void test_dns_a_response_returns_neg1_for_cname_only(void)
{
	/* ANCOUNT=1 but the record is TYPE=CNAME(5), not A */
	static const uint8_t cname_resp[] = {
		0xab, 0xcd, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00,                    /* NAME=root */
		0x00, 0x05,              /* TYPE=CNAME */
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x01,              /* RDLENGTH=1 */
		0x00,
	};
	char ip[16];

	ELA_ASSERT_INT_EQ(-1, ela_http_parse_dns_a_response(
		cname_resp, (int)sizeof(cname_resp), ip, sizeof(ip)));
}

static void test_dns_a_response_returns_neg1_when_answer_truncated(void)
{
	/* Only 15 bytes: header(12) + NAME(1) + TYPE partial — cuts off before RDLENGTH */
	char ip[16];

	ELA_ASSERT_INT_EQ(-1, ela_http_parse_dns_a_response(
		dns_a_simple, 15, ip, sizeof(ip)));
}

/* -----------------------------------------------------------------------
 * ela_http_parse_resolv_conf tests
 * ---------------------------------------------------------------------- */

static void test_parse_resolv_conf_parses_single_nameserver(void)
{
	const char *content = "nameserver 8.8.8.8\n";
	char ns[4][16];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(1, ela_http_parse_resolv_conf(f, ns, 4));
	ELA_ASSERT_STR_EQ("8.8.8.8", ns[0]);
	fclose(f);
}

static void test_parse_resolv_conf_parses_multiple_nameservers(void)
{
	const char *content = "nameserver 8.8.8.8\nnameserver 1.1.1.1\n";
	char ns[4][16];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(2, ela_http_parse_resolv_conf(f, ns, 4));
	ELA_ASSERT_STR_EQ("8.8.8.8", ns[0]);
	ELA_ASSERT_STR_EQ("1.1.1.1", ns[1]);
	fclose(f);
}

static void test_parse_resolv_conf_skips_comments_and_blank_lines(void)
{
	const char *content = "# comment\n\nnameserver 8.8.8.8\n\nsearch local\nnameserver 1.1.1.1\n";
	char ns[4][16];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(2, ela_http_parse_resolv_conf(f, ns, 4));
	ELA_ASSERT_STR_EQ("8.8.8.8", ns[0]);
	ELA_ASSERT_STR_EQ("1.1.1.1", ns[1]);
	fclose(f);
}

static void test_parse_resolv_conf_handles_leading_whitespace(void)
{
	const char *content = "  nameserver 8.8.4.4\n";
	char ns[4][16];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(1, ela_http_parse_resolv_conf(f, ns, 4));
	ELA_ASSERT_STR_EQ("8.8.4.4", ns[0]);
	fclose(f);
}

static void test_parse_resolv_conf_caps_at_max_ns(void)
{
	const char *content = "nameserver 1.1.1.1\nnameserver 2.2.2.2\nnameserver 3.3.3.3\n";
	char ns[4][16];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(2, ela_http_parse_resolv_conf(f, ns, 2));
	ELA_ASSERT_STR_EQ("1.1.1.1", ns[0]);
	ELA_ASSERT_STR_EQ("2.2.2.2", ns[1]);
	fclose(f);
}

static void test_parse_resolv_conf_handles_null_file(void)
{
	char ns[4][16];

	ELA_ASSERT_INT_EQ(0, ela_http_parse_resolv_conf(NULL, ns, 4));
}

static void test_parse_resolv_conf_returns_zero_for_empty_file(void)
{
	const char *content = "";
	char ns[4][16];
	FILE *f = fmemopen((void *)content, 1, "r"); /* fmemopen needs size >= 1 */

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(0, ela_http_parse_resolv_conf(f, ns, 4));
	fclose(f);
}

/* -----------------------------------------------------------------------
 * ela_http_parse_route_table tests
 * ---------------------------------------------------------------------- */

/*
 * A default route (destination=0, mask=0) matches any target IP because
 * (target & 0) == (0 & 0).  Use an arbitrary non-zero target to confirm
 * the matching is purely mask-based.
 */
static void test_parse_route_table_matches_default_route(void)
{
	/* /proc/net/route format: header + one default-route entry via eth0 */
	const char *content =
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
		"eth0\t00000000\t01000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n";
	char ifname[IF_NAMESIZE];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	/* 0x12345678 is an arbitrary target — the /0 default route matches it */
	ELA_ASSERT_INT_EQ(0, ela_http_parse_route_table(f, 0x12345678, ifname, sizeof(ifname)));
	ELA_ASSERT_STR_EQ("eth0", ifname);
	fclose(f);
}

static void test_parse_route_table_returns_neg1_when_flag_not_set(void)
{
	/* Flags=0x0000 — RTF_UP not set; route should be skipped */
	const char *content =
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
		"eth0\t00000000\t01000000\t0000\t0\t0\t0\t00000000\t0\t0\t0\n";
	char ifname[IF_NAMESIZE];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_http_parse_route_table(f, 0x12345678, ifname, sizeof(ifname)));
	fclose(f);
}

static void test_parse_route_table_returns_neg1_for_null_file(void)
{
	char ifname[IF_NAMESIZE];

	ELA_ASSERT_INT_EQ(-1, ela_http_parse_route_table(NULL, 0, ifname, sizeof(ifname)));
}

static void test_parse_route_table_returns_neg1_for_header_only(void)
{
	/* Only the header line — no route entries */
	const char *content =
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n";
	char ifname[IF_NAMESIZE];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_http_parse_route_table(f, 0, ifname, sizeof(ifname)));
	fclose(f);
}

static void test_parse_route_table_skips_malformed_lines(void)
{
	/* First data line is malformed (too few fields); second is valid default route */
	const char *content =
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
		"not-a-valid-route-line\n"
		"eth1\t00000000\t01000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n";
	char ifname[IF_NAMESIZE];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(0, ela_http_parse_route_table(f, 0xAABBCCDD, ifname, sizeof(ifname)));
	ELA_ASSERT_STR_EQ("eth1", ifname);
	fclose(f);
}

int run_http_client_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "http_client_parse_url_authority_and_resolve_entry", test_http_client_parse_url_authority_and_resolve_entry },
		{ "http_client_dns_query_packet_builder_encodes_labels", test_http_client_dns_query_packet_builder_encodes_labels },
		/* ela_http_parse_dns_a_response */
		{ "dns_a_response_parses_valid_response", test_dns_a_response_parses_valid_response },
		{ "dns_a_response_returns_neg1_when_too_short", test_dns_a_response_returns_neg1_when_too_short },
		{ "dns_a_response_returns_neg1_when_not_a_response", test_dns_a_response_returns_neg1_when_not_a_response },
		{ "dns_a_response_returns_neg1_when_rcode_nonzero", test_dns_a_response_returns_neg1_when_rcode_nonzero },
		{ "dns_a_response_returns_neg1_when_no_answers", test_dns_a_response_returns_neg1_when_no_answers },
		{ "dns_a_response_parses_with_question_section", test_dns_a_response_parses_with_question_section },
		{ "dns_a_response_returns_neg1_for_cname_only", test_dns_a_response_returns_neg1_for_cname_only },
		{ "dns_a_response_returns_neg1_when_answer_truncated", test_dns_a_response_returns_neg1_when_answer_truncated },
		/* ela_http_parse_resolv_conf */
		{ "parse_resolv_conf_parses_single_nameserver", test_parse_resolv_conf_parses_single_nameserver },
		{ "parse_resolv_conf_parses_multiple_nameservers", test_parse_resolv_conf_parses_multiple_nameservers },
		{ "parse_resolv_conf_skips_comments_and_blank_lines", test_parse_resolv_conf_skips_comments_and_blank_lines },
		{ "parse_resolv_conf_handles_leading_whitespace", test_parse_resolv_conf_handles_leading_whitespace },
		{ "parse_resolv_conf_caps_at_max_ns", test_parse_resolv_conf_caps_at_max_ns },
		{ "parse_resolv_conf_handles_null_file", test_parse_resolv_conf_handles_null_file },
		{ "parse_resolv_conf_returns_zero_for_empty_file", test_parse_resolv_conf_returns_zero_for_empty_file },
		/* ela_http_parse_route_table */
		{ "parse_route_table_matches_default_route", test_parse_route_table_matches_default_route },
		{ "parse_route_table_returns_neg1_when_flag_not_set", test_parse_route_table_returns_neg1_when_flag_not_set },
		{ "parse_route_table_returns_neg1_for_null_file", test_parse_route_table_returns_neg1_for_null_file },
		{ "parse_route_table_returns_neg1_for_header_only", test_parse_route_table_returns_neg1_for_header_only },
		{ "parse_route_table_skips_malformed_lines", test_parse_route_table_skips_malformed_lines },
	};

	return ela_run_test_suite("http_client_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
