// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/tcp_runtime_util.h"

static void test_tcp_runtime_nameserver_helpers(void)
{
	char ns[16];

	ELA_ASSERT_TRUE(ela_tcp_is_loopback_ipv4("127.0.0.1"));
	ELA_ASSERT_TRUE(ela_tcp_should_skip_nameserver("127.0.0.53"));
	ELA_ASSERT_FALSE(ela_tcp_should_skip_nameserver("8.8.8.8"));

	ELA_ASSERT_INT_EQ(0, ela_tcp_parse_nameserver_line("nameserver 8.8.8.8\n", ns, sizeof(ns)));
	ELA_ASSERT_STR_EQ("8.8.8.8", ns);
	ELA_ASSERT_INT_EQ(0, ela_tcp_parse_nameserver_line("  nameserver\t1.1.1.1 # comment", ns, sizeof(ns)));
	ELA_ASSERT_STR_EQ("1.1.1.1", ns);
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_nameserver_line("search example.com", ns, sizeof(ns)));
}

static void test_tcp_runtime_default_gateway_and_fallback_policy(void)
{
	char gw[32];

	ELA_ASSERT_INT_EQ(0, ela_tcp_parse_default_gateway_line(
		"eth0 00000000 0102A8C0 0003 0 0 0 00000000 0 0 0",
		gw,
		sizeof(gw)));
	ELA_ASSERT_STR_EQ("192.168.2.1", gw);
	ELA_ASSERT_INT_EQ(-1, ela_tcp_parse_default_gateway_line(
		"eth0 0002A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0",
		gw,
		sizeof(gw)));

	ELA_ASSERT_TRUE(ela_tcp_should_try_udp_resolve_fallback(-2, "ela.example"));
	ELA_ASSERT_FALSE(ela_tcp_should_try_udp_resolve_fallback(0, "ela.example"));
	ELA_ASSERT_FALSE(ela_tcp_should_try_udp_resolve_fallback(-2, "192.0.2.10"));
}

int run_tcp_runtime_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "tcp_runtime_nameserver_helpers", test_tcp_runtime_nameserver_helpers },
		{ "tcp_runtime_default_gateway_and_fallback_policy", test_tcp_runtime_default_gateway_and_fallback_policy },
	};

	return ela_run_test_suite("tcp_runtime_util", cases, sizeof(cases) / sizeof(cases[0]));
}
