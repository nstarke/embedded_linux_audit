// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/tcp_parse_util.h"

#include <string.h>

/* -----------------------------------------------------------------------
 * ela_parse_tcp_target
 * ---------------------------------------------------------------------- */

static void test_parse_tcp_target_valid_ipv4(void)
{
	char host[128];
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(0, ela_parse_tcp_target("127.0.0.1:8080", host, sizeof(host), &port));
	ELA_ASSERT_STR_EQ("127.0.0.1", host);
	ELA_ASSERT_INT_EQ(8080, port);
}

static void test_parse_tcp_target_valid_hostname(void)
{
	char host[128];
	uint16_t port = 0;

	/* ela_parse_tcp_target does not validate whether the host is an IP */
	ELA_ASSERT_INT_EQ(0, ela_parse_tcp_target("ela.example:443", host, sizeof(host), &port));
	ELA_ASSERT_STR_EQ("ela.example", host);
	ELA_ASSERT_INT_EQ(443, port);
}

static void test_parse_tcp_target_port_boundary_values(void)
{
	char host[128];
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(0, ela_parse_tcp_target("10.0.0.1:1", host, sizeof(host), &port));
	ELA_ASSERT_INT_EQ(1, port);

	ELA_ASSERT_INT_EQ(0, ela_parse_tcp_target("10.0.0.1:65535", host, sizeof(host), &port));
	ELA_ASSERT_INT_EQ(65535, port);
}

static void test_parse_tcp_target_rejects_null_and_empty(void)
{
	char host[128];
	uint16_t port;

	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target(NULL, host, sizeof(host), &port));
	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("", host, sizeof(host), &port));
	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("127.0.0.1:80", NULL, sizeof(host), &port));
	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("127.0.0.1:80", host, 0, &port));
	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("127.0.0.1:80", host, sizeof(host), NULL));
}

static void test_parse_tcp_target_rejects_missing_colon(void)
{
	char host[128];
	uint16_t port;

	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("127.0.0.1", host, sizeof(host), &port));
}

static void test_parse_tcp_target_rejects_colon_at_start(void)
{
	char host[128];
	uint16_t port;

	/* ":8080" — colon == local (first char) */
	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target(":8080", host, sizeof(host), &port));
}

static void test_parse_tcp_target_rejects_colon_at_end(void)
{
	char host[128];
	uint16_t port;

	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("127.0.0.1:", host, sizeof(host), &port));
}

static void test_parse_tcp_target_rejects_port_zero(void)
{
	char host[128];
	uint16_t port;

	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("127.0.0.1:0", host, sizeof(host), &port));
}

static void test_parse_tcp_target_rejects_port_overflow(void)
{
	char host[128];
	uint16_t port;

	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("127.0.0.1:65536", host, sizeof(host), &port));
	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("127.0.0.1:99999", host, sizeof(host), &port));
}

static void test_parse_tcp_target_rejects_non_numeric_port(void)
{
	char host[128];
	uint16_t port;

	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("127.0.0.1:http", host, sizeof(host), &port));
	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("127.0.0.1:80x", host, sizeof(host), &port));
}

static void test_parse_tcp_target_rejects_host_buffer_too_small(void)
{
	char host[4]; /* too small for "127.0.0.1" */
	uint16_t port;

	ELA_ASSERT_INT_EQ(-1, ela_parse_tcp_target("127.0.0.1:80", host, sizeof(host), &port));
}

/* -----------------------------------------------------------------------
 * ela_is_valid_ipv4_tcp_target
 * ---------------------------------------------------------------------- */

static void test_is_valid_ipv4_tcp_target_accepts_dotted_decimal(void)
{
	ELA_ASSERT_TRUE(ela_is_valid_ipv4_tcp_target("192.168.1.1:80"));
	ELA_ASSERT_TRUE(ela_is_valid_ipv4_tcp_target("10.0.0.1:443"));
	ELA_ASSERT_TRUE(ela_is_valid_ipv4_tcp_target("0.0.0.0:1"));
}

static void test_is_valid_ipv4_tcp_target_rejects_hostname(void)
{
	ELA_ASSERT_FALSE(ela_is_valid_ipv4_tcp_target("localhost:8080"));
	ELA_ASSERT_FALSE(ela_is_valid_ipv4_tcp_target("ela.example:443"));
}

static void test_is_valid_ipv4_tcp_target_rejects_invalid_inputs(void)
{
	ELA_ASSERT_FALSE(ela_is_valid_ipv4_tcp_target(NULL));
	ELA_ASSERT_FALSE(ela_is_valid_ipv4_tcp_target(""));
	ELA_ASSERT_FALSE(ela_is_valid_ipv4_tcp_target("no-port"));
	/* Invalid octet */
	ELA_ASSERT_FALSE(ela_is_valid_ipv4_tcp_target("300.0.0.1:80"));
}

/* -----------------------------------------------------------------------
 * ela_dns_build_query_packet
 * ---------------------------------------------------------------------- */

static void test_dns_build_query_encodes_labels(void)
{
	uint8_t buf[128];
	int len;

	len = ela_dns_build_query_packet("ela.example", buf, (int)sizeof(buf));
	ELA_ASSERT_TRUE(len > 20);
	/* Fixed header bytes */
	ELA_ASSERT_INT_EQ(0xab, buf[0]);
	ELA_ASSERT_INT_EQ(0xcd, buf[1]);
	ELA_ASSERT_INT_EQ(0x01, buf[2]); /* QR=0, RD=1 */
	ELA_ASSERT_INT_EQ(0x00, buf[3]);
	ELA_ASSERT_INT_EQ(0x00, buf[4]);
	ELA_ASSERT_INT_EQ(0x01, buf[5]); /* QDCOUNT=1 */
	/* First label: length=3, then "ela" */
	ELA_ASSERT_INT_EQ(3, buf[12]);
	ELA_ASSERT_INT_EQ('e', buf[13]);
	ELA_ASSERT_INT_EQ('l', buf[14]);
	ELA_ASSERT_INT_EQ('a', buf[15]);
	/* Second label: length=7, then "example" */
	ELA_ASSERT_INT_EQ(7, buf[16]);
}

static void test_dns_build_query_rejects_null_and_short_buffer(void)
{
	uint8_t buf[64];

	ELA_ASSERT_INT_EQ(-1, ela_dns_build_query_packet(NULL, buf, (int)sizeof(buf)));
	ELA_ASSERT_INT_EQ(-1, ela_dns_build_query_packet("ela.example", NULL, 64));
	ELA_ASSERT_INT_EQ(-1, ela_dns_build_query_packet("ela.example", buf, 31));
}

static void test_dns_build_query_rejects_label_too_long(void)
{
	uint8_t buf[128];
	/* A label >63 chars is invalid per DNS spec */
	const char *long_label =
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		".example";

	ELA_ASSERT_INT_EQ(-1, ela_dns_build_query_packet(long_label, buf, (int)sizeof(buf)));
}

/* -----------------------------------------------------------------------
 * ela_dns_extract_first_a_record
 * ---------------------------------------------------------------------- */

/*
 * Full response with one question ("ela.example") and one A answer (192.0.2.10)
 * using a pointer (0xc0 0x0c) for the answer name.
 */
static const uint8_t dns_resp_valid[] = {
	0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x03, 'e', 'l', 'a', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
	0x00, 0x01, 0x00, 0x01,
	0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
	192, 0, 2, 10,
};

static void test_dns_extract_a_record_valid(void)
{
	char ip[32];

	ELA_ASSERT_INT_EQ(0, ela_dns_extract_first_a_record(
		dns_resp_valid, sizeof(dns_resp_valid), ip, sizeof(ip)));
	ELA_ASSERT_STR_EQ("192.0.2.10", ip);
}

static void test_dns_extract_a_record_rejects_null_and_short(void)
{
	char ip[32];

	ELA_ASSERT_INT_EQ(-1, ela_dns_extract_first_a_record(NULL, 20, ip, sizeof(ip)));
	ELA_ASSERT_INT_EQ(-1, ela_dns_extract_first_a_record(dns_resp_valid, 11, ip, sizeof(ip)));
	ELA_ASSERT_INT_EQ(-1, ela_dns_extract_first_a_record(dns_resp_valid, sizeof(dns_resp_valid), NULL, 32));
	ELA_ASSERT_INT_EQ(-1, ela_dns_extract_first_a_record(dns_resp_valid, sizeof(dns_resp_valid), ip, 0));
}

static void test_dns_extract_a_record_rejects_query_packet(void)
{
	/* resp[2] = 0x01: QR bit clear — this is a query */
	static const uint8_t query_pkt[] = {
		0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01,
	};
	char ip[32];

	ELA_ASSERT_INT_EQ(-1, ela_dns_extract_first_a_record(
		query_pkt, sizeof(query_pkt), ip, sizeof(ip)));
}

static void test_dns_extract_a_record_rejects_nonzero_rcode(void)
{
	/* RCODE=3 (NXDOMAIN) */
	static const uint8_t nxdomain[] = {
		0xab, 0xcd, 0x81, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	char ip[32];

	ELA_ASSERT_INT_EQ(-1, ela_dns_extract_first_a_record(
		nxdomain, sizeof(nxdomain), ip, sizeof(ip)));
}

static void test_dns_extract_a_record_rejects_zero_ancount(void)
{
	/* Valid response flags, ANCOUNT=0 */
	static const uint8_t empty[] = {
		0xab, 0xcd, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	char ip[32];

	ELA_ASSERT_INT_EQ(-1, ela_dns_extract_first_a_record(
		empty, sizeof(empty), ip, sizeof(ip)));
}

static void test_dns_extract_a_record_returns_neg1_for_cname_only(void)
{
	/* ANCOUNT=1 but TYPE=CNAME(5), not A */
	static const uint8_t cname_resp[] = {
		0xab, 0xcd, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00,                    /* NAME=root */
		0x00, 0x05,              /* TYPE=CNAME */
		0x00, 0x01,              /* CLASS=IN */
		0x00, 0x00, 0x00, 0x3c,  /* TTL */
		0x00, 0x01,              /* RDLENGTH=1 */
		0x00,                    /* RDATA */
	};
	char ip[32];

	ELA_ASSERT_INT_EQ(-1, ela_dns_extract_first_a_record(
		cname_resp, sizeof(cname_resp), ip, sizeof(ip)));
}

static void test_dns_extract_a_record_returns_neg1_when_truncated(void)
{
	/* Truncated: only header + NAME byte; answer fixed fields cut off */
	char ip[32];

	ELA_ASSERT_INT_EQ(-1, ela_dns_extract_first_a_record(
		dns_resp_valid, 14, ip, sizeof(ip)));
}

static void test_dns_extract_a_record_simple_no_question(void)
{
	/*
	 * No question section (QDCOUNT=0), one A answer with root label name.
	 * Answer: NAME=root, TYPE=A, CLASS=IN, TTL=60, RDLENGTH=4, 10.0.0.1
	 */
	static const uint8_t simple[] = {
		0xab, 0xcd, 0x81, 0x80,
		0x00, 0x00,              /* QDCOUNT=0 */
		0x00, 0x01,              /* ANCOUNT=1 */
		0x00, 0x00, 0x00, 0x00,
		0x00,                    /* NAME=root */
		0x00, 0x01,              /* TYPE=A */
		0x00, 0x01,              /* CLASS=IN */
		0x00, 0x00, 0x00, 0x3c,  /* TTL=60 */
		0x00, 0x04,              /* RDLENGTH=4 */
		10, 0, 0, 1,             /* 10.0.0.1 */
	};
	char ip[32];

	ELA_ASSERT_INT_EQ(0, ela_dns_extract_first_a_record(
		simple, sizeof(simple), ip, sizeof(ip)));
	ELA_ASSERT_STR_EQ("10.0.0.1", ip);
}

static void test_dns_extract_a_record_rejects_oversized_label_in_question(void)
{
	/*
	 * QDCOUNT=1; label length byte 5 claims 5 chars follow, but only 1
	 * byte remains after it (resp_len=14, pos=12: 14-12-1=1 < 5).
	 * Top bits are 0 so it's not a compression pointer.
	 * The bounds guard in the question-section loop must return -1.
	 */
	static const uint8_t pkt[] = {
		0xab, 0xcd, 0x81, 0x80,
		0x00, 0x01,              /* QDCOUNT=1 */
		0x00, 0x01,              /* ANCOUNT=1 */
		0x00, 0x00, 0x00, 0x00,
		0x05, 'x',               /* label len=5, only 1 byte present */
	};
	char ip[32];

	ELA_ASSERT_INT_EQ(-1, ela_dns_extract_first_a_record(
		pkt, sizeof(pkt), ip, sizeof(ip)));
}

static void test_dns_extract_a_record_rejects_oversized_label_in_answer(void)
{
	/*
	 * QDCOUNT=0, ANCOUNT=1; answer NAME label length 5 claims 5 chars but
	 * only 1 byte remains (resp_len=14, pos=12: 14-12-1=1 < 5).
	 * Top bits are 0 so it's not a compression pointer.
	 * The bounds guard in the answer-section loop must return -1.
	 */
	static const uint8_t pkt[] = {
		0xab, 0xcd, 0x81, 0x80,
		0x00, 0x00,              /* QDCOUNT=0 */
		0x00, 0x01,              /* ANCOUNT=1 */
		0x00, 0x00, 0x00, 0x00,
		0x05, 'x',               /* answer name: label len=5, 1 byte present */
	};
	char ip[32];

	ELA_ASSERT_INT_EQ(-1, ela_dns_extract_first_a_record(
		pkt, sizeof(pkt), ip, sizeof(ip)));
}

int run_tcp_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* ela_parse_tcp_target */
		{ "parse_tcp_target_valid_ipv4", test_parse_tcp_target_valid_ipv4 },
		{ "parse_tcp_target_valid_hostname", test_parse_tcp_target_valid_hostname },
		{ "parse_tcp_target_port_boundary_values", test_parse_tcp_target_port_boundary_values },
		{ "parse_tcp_target_rejects_null_and_empty", test_parse_tcp_target_rejects_null_and_empty },
		{ "parse_tcp_target_rejects_missing_colon", test_parse_tcp_target_rejects_missing_colon },
		{ "parse_tcp_target_rejects_colon_at_start", test_parse_tcp_target_rejects_colon_at_start },
		{ "parse_tcp_target_rejects_colon_at_end", test_parse_tcp_target_rejects_colon_at_end },
		{ "parse_tcp_target_rejects_port_zero", test_parse_tcp_target_rejects_port_zero },
		{ "parse_tcp_target_rejects_port_overflow", test_parse_tcp_target_rejects_port_overflow },
		{ "parse_tcp_target_rejects_non_numeric_port", test_parse_tcp_target_rejects_non_numeric_port },
		{ "parse_tcp_target_rejects_host_buffer_too_small", test_parse_tcp_target_rejects_host_buffer_too_small },
		/* ela_is_valid_ipv4_tcp_target */
		{ "is_valid_ipv4_tcp_target_accepts_dotted_decimal", test_is_valid_ipv4_tcp_target_accepts_dotted_decimal },
		{ "is_valid_ipv4_tcp_target_rejects_hostname", test_is_valid_ipv4_tcp_target_rejects_hostname },
		{ "is_valid_ipv4_tcp_target_rejects_invalid_inputs", test_is_valid_ipv4_tcp_target_rejects_invalid_inputs },
		/* ela_dns_build_query_packet */
		{ "dns_build_query_encodes_labels", test_dns_build_query_encodes_labels },
		{ "dns_build_query_rejects_null_and_short_buffer", test_dns_build_query_rejects_null_and_short_buffer },
		{ "dns_build_query_rejects_label_too_long", test_dns_build_query_rejects_label_too_long },
		/* ela_dns_extract_first_a_record */
		{ "dns_extract_a_record_valid", test_dns_extract_a_record_valid },
		{ "dns_extract_a_record_rejects_null_and_short", test_dns_extract_a_record_rejects_null_and_short },
		{ "dns_extract_a_record_rejects_query_packet", test_dns_extract_a_record_rejects_query_packet },
		{ "dns_extract_a_record_rejects_nonzero_rcode", test_dns_extract_a_record_rejects_nonzero_rcode },
		{ "dns_extract_a_record_rejects_zero_ancount", test_dns_extract_a_record_rejects_zero_ancount },
		{ "dns_extract_a_record_returns_neg1_for_cname_only", test_dns_extract_a_record_returns_neg1_for_cname_only },
		{ "dns_extract_a_record_returns_neg1_when_truncated", test_dns_extract_a_record_returns_neg1_when_truncated },
		{ "dns_extract_a_record_simple_no_question", test_dns_extract_a_record_simple_no_question },
		{ "dns_extract_a_record_rejects_oversized_label_in_question", test_dns_extract_a_record_rejects_oversized_label_in_question },
		{ "dns_extract_a_record_rejects_oversized_label_in_answer", test_dns_extract_a_record_rejects_oversized_label_in_answer },
	};

	return ela_run_test_suite("tcp_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
