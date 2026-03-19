// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ws_url_util.h"

static void test_ws_base64_encode_matches_known_value(void)
{
	char out[16];
	const unsigned char in[] = { 'f', 'o', 'o' };

	ela_ws_base64_encode(in, sizeof(in), out, sizeof(out));
	ELA_ASSERT_STR_EQ("Zm9v", out);
}

static void test_ws_parse_url_handles_defaults_and_explicit_port(void)
{
	char host[128];
	char path[128];
	uint16_t port = 0;
	int is_tls = 0;

	ELA_ASSERT_INT_EQ(0, ela_ws_parse_url("wss://ela.example/socket", host, sizeof(host), &port, path, sizeof(path), &is_tls));
	ELA_ASSERT_STR_EQ("ela.example", host);
	ELA_ASSERT_INT_EQ(443, port);
	ELA_ASSERT_STR_EQ("/socket", path);
	ELA_ASSERT_INT_EQ(1, is_tls);

	ELA_ASSERT_INT_EQ(0, ela_ws_parse_url("ws://ela.example:9000", host, sizeof(host), &port, path, sizeof(path), &is_tls));
	ELA_ASSERT_INT_EQ(9000, port);
	ELA_ASSERT_STR_EQ("/", path);
	ELA_ASSERT_INT_EQ(0, is_tls);
}

static void test_ws_builders_generate_terminal_url_and_handshake(void)
{
	char url[256];
	char req[512];

	ELA_ASSERT_INT_EQ(0, ela_ws_build_terminal_url("wss://ela.example/api/", "aa-bb", url, sizeof(url)));
	ELA_ASSERT_STR_EQ("wss://ela.example/api/terminal/aa-bb", url);

	ELA_ASSERT_TRUE(ela_ws_build_handshake_request(req, sizeof(req), "ela.example", 443, "/terminal/aa-bb", 1, "token123", "abc123==") > 0);
	ELA_ASSERT_TRUE(strstr(req, "GET /terminal/aa-bb HTTP/1.1\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(req, "Host: ela.example\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(req, "Authorization: Bearer token123\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(req, "Sec-WebSocket-Key: abc123==\r\n") != NULL);
}

int run_ws_url_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "ws_base64_encode_matches_known_value", test_ws_base64_encode_matches_known_value },
		{ "ws_parse_url_handles_defaults_and_explicit_port", test_ws_parse_url_handles_defaults_and_explicit_port },
		{ "ws_builders_generate_terminal_url_and_handshake", test_ws_builders_generate_terminal_url_and_handshake },
	};

	return ela_run_test_suite("ws_url_util", cases, sizeof(cases) / sizeof(cases[0]));
}
