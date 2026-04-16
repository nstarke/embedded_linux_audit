// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/tcp_runtime_util.h"

#include <net/if.h>
#include <stdio.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * ela_tcp_is_loopback_ipv4
 * ---------------------------------------------------------------------- */

static void test_is_loopback_ipv4_identifies_loopback_range(void)
{
	ELA_ASSERT_TRUE(ela_tcp_is_loopback_ipv4("127.0.0.1"));
	ELA_ASSERT_TRUE(ela_tcp_is_loopback_ipv4("127.255.255.254"));
	ELA_ASSERT_TRUE(ela_tcp_is_loopback_ipv4("127.0.0.53"));
}

static void test_is_loopback_ipv4_rejects_non_loopback(void)
{
	ELA_ASSERT_FALSE(ela_tcp_is_loopback_ipv4("128.0.0.1"));
	ELA_ASSERT_FALSE(ela_tcp_is_loopback_ipv4("10.0.0.1"));
	ELA_ASSERT_FALSE(ela_tcp_is_loopback_ipv4("192.168.1.1"));
	ELA_ASSERT_FALSE(ela_tcp_is_loopback_ipv4("0.0.0.0"));
}

static void test_is_loopback_ipv4_handles_null_and_empty(void)
{
	ELA_ASSERT_FALSE(ela_tcp_is_loopback_ipv4(NULL));
	ELA_ASSERT_FALSE(ela_tcp_is_loopback_ipv4(""));
}

/* -----------------------------------------------------------------------
 * ela_tcp_should_skip_nameserver
 * ---------------------------------------------------------------------- */

static void test_should_skip_nameserver_skips_loopback(void)
{
	ELA_ASSERT_TRUE(ela_tcp_should_skip_nameserver("127.0.0.1"));
	ELA_ASSERT_TRUE(ela_tcp_should_skip_nameserver("127.0.0.53"));
}

static void test_should_skip_nameserver_keeps_public_dns(void)
{
	ELA_ASSERT_FALSE(ela_tcp_should_skip_nameserver("8.8.8.8"));
	ELA_ASSERT_FALSE(ela_tcp_should_skip_nameserver("1.1.1.1"));
	ELA_ASSERT_FALSE(ela_tcp_should_skip_nameserver("192.168.1.1"));
}

static void test_should_skip_nameserver_skips_null_and_empty(void)
{
	ELA_ASSERT_TRUE(ela_tcp_should_skip_nameserver(NULL));
	ELA_ASSERT_TRUE(ela_tcp_should_skip_nameserver(""));
}

/* -----------------------------------------------------------------------
 * ela_tcp_parse_nameserver_line
 * ---------------------------------------------------------------------- */

static void test_parse_nameserver_line_plain(void)
{
	char ns[16];

	ELA_ASSERT_INT_EQ(0, ela_tcp_parse_nameserver_line("nameserver 8.8.8.8\n", ns, sizeof(ns)));
	ELA_ASSERT_STR_EQ("8.8.8.8", ns);
}

static void test_parse_nameserver_line_with_leading_whitespace_and_comment(void)
{
	char ns[16];

	ELA_ASSERT_INT_EQ(0, ela_tcp_parse_nameserver_line("  nameserver\t1.1.1.1 # comment", ns, sizeof(ns)));
	ELA_ASSERT_STR_EQ("1.1.1.1", ns);
}

static void test_parse_nameserver_line_rejects_non_nameserver(void)
{
	char ns[16];

	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_nameserver_line("search example.com", ns, sizeof(ns)));
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_nameserver_line("# nameserver 8.8.8.8", ns, sizeof(ns)));
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_nameserver_line("domain local", ns, sizeof(ns)));
}

static void test_parse_nameserver_line_rejects_empty_address(void)
{
	char ns[16];

	/* "nameserver" keyword present but nothing after it */
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_nameserver_line("nameserver\n", ns, sizeof(ns)));
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_nameserver_line("nameserver # inline\n", ns, sizeof(ns)));
}

static void test_parse_nameserver_line_rejects_null_inputs(void)
{
	char ns[16];

	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_nameserver_line(NULL, ns, sizeof(ns)));
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_nameserver_line("nameserver 8.8.8.8", NULL, 16));
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_nameserver_line("nameserver 8.8.8.8", ns, 0));
}

static void test_parse_nameserver_line_rejects_buffer_too_small(void)
{
	char ns[4]; /* too small for "8.8.8.8" */

	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_nameserver_line("nameserver 8.8.8.8\n", ns, sizeof(ns)));
}

/* -----------------------------------------------------------------------
 * ela_tcp_parse_default_gateway_line
 * ---------------------------------------------------------------------- */

static void test_parse_default_gateway_line_valid(void)
{
	char gw[32];

	/* destination=0 (default), gateway=0xC0A80201=192.168.2.1, flags has GW bit (0x0002) */
	ELA_ASSERT_INT_EQ(0, ela_tcp_parse_default_gateway_line(
		"eth0 00000000 0102A8C0 0003 0 0 0 00000000 0 0 0",
		gw, sizeof(gw)));
	ELA_ASSERT_STR_EQ("192.168.2.1", gw);
}

static void test_parse_default_gateway_line_rejects_non_default_route(void)
{
	char gw[32];

	/* destination != 0 */
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_default_gateway_line(
		"eth0 0002A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0",
		gw, sizeof(gw)));
}

static void test_parse_default_gateway_line_rejects_missing_gw_flag(void)
{
	char gw[32];

	/* destination=0, gateway non-zero, but flags=0x0001 (RTF_UP only, no RTF_GATEWAY 0x0002) */
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_default_gateway_line(
		"eth0 00000000 0102A8C0 0001 0 0 0 00000000 0 0 0",
		gw, sizeof(gw)));
}

static void test_parse_default_gateway_line_rejects_zero_gateway(void)
{
	char gw[32];

	/* destination=0, flags has GW bit, but gateway=0 */
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_default_gateway_line(
		"eth0 00000000 00000000 0003 0 0 0 00000000 0 0 0",
		gw, sizeof(gw)));
}

static void test_parse_default_gateway_line_rejects_null_inputs(void)
{
	char gw[32];

	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_default_gateway_line(NULL, gw, sizeof(gw)));
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_default_gateway_line(
		"eth0 00000000 0102A8C0 0003 0 0 0 00000000 0 0 0", NULL, 32));
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_default_gateway_line(
		"eth0 00000000 0102A8C0 0003 0 0 0 00000000 0 0 0", gw, 0));
}

static void test_parse_default_gateway_line_rejects_malformed(void)
{
	char gw[32];

	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_default_gateway_line("not-enough-fields", gw, sizeof(gw)));
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_default_gateway_line("", gw, sizeof(gw)));
}

/* -----------------------------------------------------------------------
 * ela_tcp_should_try_udp_resolve_fallback
 * ---------------------------------------------------------------------- */

static void test_should_try_udp_resolve_fallback_on_hostname_failure(void)
{
	/* rc != 0 and host is not a numeric IP => try UDP fallback */
	ELA_ASSERT_TRUE(ela_tcp_should_try_udp_resolve_fallback(-2, "ela.example"));
	ELA_ASSERT_TRUE(ela_tcp_should_try_udp_resolve_fallback(-1, "api.server.local"));
}

static void test_should_not_try_udp_resolve_when_rc_zero(void)
{
	/* getaddrinfo succeeded */
	ELA_ASSERT_FALSE(ela_tcp_should_try_udp_resolve_fallback(0, "ela.example"));
}

static void test_should_not_try_udp_resolve_for_ip_address(void)
{
	/* host is already a numeric IP — no need for DNS */
	ELA_ASSERT_FALSE(ela_tcp_should_try_udp_resolve_fallback(-2, "192.0.2.10"));
	ELA_ASSERT_FALSE(ela_tcp_should_try_udp_resolve_fallback(-2, "10.0.0.1"));
}

static void test_should_not_try_udp_resolve_for_null_or_empty_host(void)
{
	ELA_ASSERT_FALSE(ela_tcp_should_try_udp_resolve_fallback(-2, NULL));
	ELA_ASSERT_FALSE(ela_tcp_should_try_udp_resolve_fallback(-2, ""));
}

/* -----------------------------------------------------------------------
 * ela_tcp_has_nameserver_in_file
 * ---------------------------------------------------------------------- */

static void test_has_nameserver_in_file_finds_nameserver(void)
{
	const char *content = "# comment\nnameserver 8.8.8.8\n";
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(1, ela_tcp_has_nameserver_in_file(f));
	fclose(f);
}

static void test_has_nameserver_in_file_returns_zero_when_none(void)
{
	const char *content = "# only comments\nsearch local\n";
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(0, ela_tcp_has_nameserver_in_file(f));
	fclose(f);
}

static void test_has_nameserver_in_file_returns_zero_for_null(void)
{
	ELA_ASSERT_INT_EQ(0, ela_tcp_has_nameserver_in_file(NULL));
}

/* -----------------------------------------------------------------------
 * ela_tcp_read_nameservers_from_file
 * ---------------------------------------------------------------------- */

static void test_read_nameservers_from_file_parses_multiple(void)
{
	const char *content = "nameserver 8.8.8.8\nnameserver 1.1.1.1\n";
	char ns[4][16];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(2, ela_tcp_read_nameservers_from_file(f, ns, 4));
	ELA_ASSERT_STR_EQ("8.8.8.8", ns[0]);
	ELA_ASSERT_STR_EQ("1.1.1.1", ns[1]);
	fclose(f);
}

static void test_read_nameservers_from_file_caps_at_max(void)
{
	const char *content =
		"nameserver 1.1.1.1\nnameserver 2.2.2.2\nnameserver 3.3.3.3\n";
	char ns[4][16];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(2, ela_tcp_read_nameservers_from_file(f, ns, 2));
	ELA_ASSERT_STR_EQ("1.1.1.1", ns[0]);
	ELA_ASSERT_STR_EQ("2.2.2.2", ns[1]);
	fclose(f);
}

static void test_read_nameservers_from_file_returns_zero_for_null(void)
{
	char ns[4][16];

	ELA_ASSERT_INT_EQ(0, ela_tcp_read_nameservers_from_file(NULL, ns, 4));
	ELA_ASSERT_INT_EQ(0, ela_tcp_read_nameservers_from_file(NULL, NULL, 4));
}

static void test_read_nameservers_from_file_skips_comments(void)
{
	const char *content = "# resolver\nsearch local\nnameserver 9.9.9.9\n";
	char ns[4][16];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(1, ela_tcp_read_nameservers_from_file(f, ns, 4));
	ELA_ASSERT_STR_EQ("9.9.9.9", ns[0]);
	fclose(f);
}

/* -----------------------------------------------------------------------
 * ela_tcp_get_gateway_from_route_file
 * ---------------------------------------------------------------------- */

static void test_get_gateway_from_route_file_finds_default_route(void)
{
	/* /proc/net/route format: header + one default-route entry */
	const char *content =
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
		"eth0\t00000000\t0102A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
	char gw[32];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(0, ela_tcp_get_gateway_from_route_file(f, gw, sizeof(gw)));
	ELA_ASSERT_STR_EQ("192.168.2.1", gw);
	fclose(f);
}

static void test_get_gateway_from_route_file_returns_neg1_when_no_default(void)
{
	/* Only non-default routes (destination != 0) */
	const char *content =
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
	char gw[32];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_tcp_get_gateway_from_route_file(f, gw, sizeof(gw)));
	fclose(f);
}

static void test_get_gateway_from_route_file_returns_neg1_for_header_only(void)
{
	const char *content =
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n";
	char gw[32];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_tcp_get_gateway_from_route_file(f, gw, sizeof(gw)));
	fclose(f);
}

static void test_get_gateway_from_route_file_returns_neg1_for_null(void)
{
	char gw[32];

	ELA_ASSERT_INT_EQ(-1, ela_tcp_get_gateway_from_route_file(NULL, gw, sizeof(gw)));
}

static void test_get_gateway_from_route_file_skips_non_default_and_finds_default(void)
{
	/* First entry is a host route; second is the default */
	const char *content =
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
	char gw[32];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(0, ela_tcp_get_gateway_from_route_file(f, gw, sizeof(gw)));
	ELA_ASSERT_STR_EQ("192.168.1.1", gw);
	fclose(f);
}

static void test_get_gateway_from_route_file_skips_tunnel_default_route(void)
{
	/*
	 * Simulates the Aruba AP routing table where two default routes exist:
	 *   tun0: destination=0, gateway=0, flags=0x0001 (UP only, no RTF_GATEWAY)
	 *         — this is the control tunnel; must be skipped
	 *   br0:  destination=0, gateway=192.168.35.1, flags=0x0003 (UP+GATEWAY)
	 *         — this is the real internet interface; must be returned
	 *
	 * 192.168.35.1 in little-endian hex = 0x0123A8C0
	 */
	const char *content =
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
		"tun0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"
		"br0\t00000000\t0123A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
	char gw[32];
	FILE *f = fmemopen((void *)content, strlen(content), "r");

	ELA_ASSERT_TRUE(f != NULL);
	ELA_ASSERT_INT_EQ(0, ela_tcp_get_gateway_from_route_file(f, gw, sizeof(gw)));
	ELA_ASSERT_STR_EQ("192.168.35.1", gw);
	fclose(f);
}

int run_tcp_runtime_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* ela_tcp_is_loopback_ipv4 */
		{ "is_loopback_ipv4_identifies_loopback_range", test_is_loopback_ipv4_identifies_loopback_range },
		{ "is_loopback_ipv4_rejects_non_loopback", test_is_loopback_ipv4_rejects_non_loopback },
		{ "is_loopback_ipv4_handles_null_and_empty", test_is_loopback_ipv4_handles_null_and_empty },
		/* ela_tcp_should_skip_nameserver */
		{ "should_skip_nameserver_skips_loopback", test_should_skip_nameserver_skips_loopback },
		{ "should_skip_nameserver_keeps_public_dns", test_should_skip_nameserver_keeps_public_dns },
		{ "should_skip_nameserver_skips_null_and_empty", test_should_skip_nameserver_skips_null_and_empty },
		/* ela_tcp_parse_nameserver_line */
		{ "parse_nameserver_line_plain", test_parse_nameserver_line_plain },
		{ "parse_nameserver_line_with_leading_whitespace_and_comment", test_parse_nameserver_line_with_leading_whitespace_and_comment },
		{ "parse_nameserver_line_rejects_non_nameserver", test_parse_nameserver_line_rejects_non_nameserver },
		{ "parse_nameserver_line_rejects_empty_address", test_parse_nameserver_line_rejects_empty_address },
		{ "parse_nameserver_line_rejects_null_inputs", test_parse_nameserver_line_rejects_null_inputs },
		{ "parse_nameserver_line_rejects_buffer_too_small", test_parse_nameserver_line_rejects_buffer_too_small },
		/* ela_tcp_parse_default_gateway_line */
		{ "parse_default_gateway_line_valid", test_parse_default_gateway_line_valid },
		{ "parse_default_gateway_line_rejects_non_default_route", test_parse_default_gateway_line_rejects_non_default_route },
		{ "parse_default_gateway_line_rejects_missing_gw_flag", test_parse_default_gateway_line_rejects_missing_gw_flag },
		{ "parse_default_gateway_line_rejects_zero_gateway", test_parse_default_gateway_line_rejects_zero_gateway },
		{ "parse_default_gateway_line_rejects_null_inputs", test_parse_default_gateway_line_rejects_null_inputs },
		{ "parse_default_gateway_line_rejects_malformed", test_parse_default_gateway_line_rejects_malformed },
		/* ela_tcp_should_try_udp_resolve_fallback */
		{ "should_try_udp_resolve_fallback_on_hostname_failure", test_should_try_udp_resolve_fallback_on_hostname_failure },
		{ "should_not_try_udp_resolve_when_rc_zero", test_should_not_try_udp_resolve_when_rc_zero },
		{ "should_not_try_udp_resolve_for_ip_address", test_should_not_try_udp_resolve_for_ip_address },
		{ "should_not_try_udp_resolve_for_null_or_empty_host", test_should_not_try_udp_resolve_for_null_or_empty_host },
		/* ela_tcp_has_nameserver_in_file */
		{ "has_nameserver_in_file_finds_nameserver", test_has_nameserver_in_file_finds_nameserver },
		{ "has_nameserver_in_file_returns_zero_when_none", test_has_nameserver_in_file_returns_zero_when_none },
		{ "has_nameserver_in_file_returns_zero_for_null", test_has_nameserver_in_file_returns_zero_for_null },
		/* ela_tcp_read_nameservers_from_file */
		{ "read_nameservers_from_file_parses_multiple", test_read_nameservers_from_file_parses_multiple },
		{ "read_nameservers_from_file_caps_at_max", test_read_nameservers_from_file_caps_at_max },
		{ "read_nameservers_from_file_returns_zero_for_null", test_read_nameservers_from_file_returns_zero_for_null },
		{ "read_nameservers_from_file_skips_comments", test_read_nameservers_from_file_skips_comments },
		/* ela_tcp_get_gateway_from_route_file */
		{ "get_gateway_from_route_file_finds_default_route", test_get_gateway_from_route_file_finds_default_route },
		{ "get_gateway_from_route_file_returns_neg1_when_no_default", test_get_gateway_from_route_file_returns_neg1_when_no_default },
		{ "get_gateway_from_route_file_returns_neg1_for_header_only", test_get_gateway_from_route_file_returns_neg1_for_header_only },
		{ "get_gateway_from_route_file_returns_neg1_for_null", test_get_gateway_from_route_file_returns_neg1_for_null },
		{ "get_gateway_from_route_file_skips_non_default_and_finds_default", test_get_gateway_from_route_file_skips_non_default_and_finds_default },
		{ "get_gateway_from_route_file_skips_tunnel_default_route", test_get_gateway_from_route_file_skips_tunnel_default_route },
	};

	return ela_run_test_suite("tcp_runtime_util", cases, sizeof(cases) / sizeof(cases[0]));
}
