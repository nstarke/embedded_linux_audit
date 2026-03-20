// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ws_url_util.h"

#include <stdint.h>
#include <string.h>

/* =========================================================================
 * ela_ws_base64_encode
 * ====================================================================== */

static void test_base64_three_bytes_foo(void)
{
	char out[16];
	const unsigned char in[] = { 'f', 'o', 'o' };

	ela_ws_base64_encode(in, sizeof(in), out, sizeof(out));
	ELA_ASSERT_STR_EQ("Zm9v", out);
}

static void test_base64_one_byte_has_double_padding(void)
{
	char out[16];
	const unsigned char in[] = { 'A' };

	/* 'A' = 0x41 → QQ== */
	ela_ws_base64_encode(in, sizeof(in), out, sizeof(out));
	ELA_ASSERT_STR_EQ("QQ==", out);
}

static void test_base64_two_bytes_has_single_padding(void)
{
	char out[16];
	const unsigned char in[] = { 'f', 'o' };

	/* "fo" → Zm8= */
	ela_ws_base64_encode(in, sizeof(in), out, sizeof(out));
	ELA_ASSERT_STR_EQ("Zm8=", out);
}

static void test_base64_empty_no_crash(void)
{
	char out[16] = "sentinel000";

	ela_ws_base64_encode((const unsigned char *)"", 0, out, sizeof(out));
	/* output buffer must be NUL-terminated and empty */
	ELA_ASSERT_INT_EQ('\0', out[0]);
}

/* =========================================================================
 * ela_ws_parse_url
 * ====================================================================== */

static void test_parse_url_null_url_returns_minus1(void)
{
	char host[64], path[64];
	uint16_t port = 0;
	int tls = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ws_parse_url(NULL, host, sizeof(host), &port, path, sizeof(path), &tls));
}

static void test_parse_url_null_host_returns_minus1(void)
{
	char path[64];
	uint16_t port = 0;
	int tls = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ws_parse_url("wss://h/p", NULL, 64, &port, path, sizeof(path), &tls));
}

static void test_parse_url_unknown_scheme_returns_minus1(void)
{
	char host[64], path[64];
	uint16_t port = 0;
	int tls = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ws_parse_url("http://host/path", host, sizeof(host), &port, path, sizeof(path), &tls));
}

static void test_parse_url_wss_defaults(void)
{
	char host[64], path[64];
	uint16_t port = 0;
	int tls = 0;

	ELA_ASSERT_INT_EQ(0, ela_ws_parse_url("wss://ela.example/socket", host, sizeof(host), &port, path, sizeof(path), &tls));
	ELA_ASSERT_STR_EQ("ela.example", host);
	ELA_ASSERT_INT_EQ(443, (int)port);
	ELA_ASSERT_STR_EQ("/socket", path);
	ELA_ASSERT_INT_EQ(1, tls);
}

static void test_parse_url_ws_default_port_80(void)
{
	char host[64], path[64];
	uint16_t port = 0;
	int tls = 0;

	ELA_ASSERT_INT_EQ(0, ela_ws_parse_url("ws://host.example/path", host, sizeof(host), &port, path, sizeof(path), &tls));
	ELA_ASSERT_INT_EQ(80, (int)port);
	ELA_ASSERT_INT_EQ(0, tls);
}

static void test_parse_url_explicit_port(void)
{
	char host[64], path[64];
	uint16_t port = 0;
	int tls = 0;

	ELA_ASSERT_INT_EQ(0, ela_ws_parse_url("ws://ela.example:9000", host, sizeof(host), &port, path, sizeof(path), &tls));
	ELA_ASSERT_INT_EQ(9000, (int)port);
	ELA_ASSERT_STR_EQ("/", path);
}

static void test_parse_url_no_path_defaults_to_slash(void)
{
	char host[64], path[64];
	uint16_t port = 0;
	int tls = 0;

	ELA_ASSERT_INT_EQ(0, ela_ws_parse_url("wss://ela.example", host, sizeof(host), &port, path, sizeof(path), &tls));
	ELA_ASSERT_STR_EQ("/", path);
}

/* =========================================================================
 * ela_ws_build_terminal_url
 * ====================================================================== */

static void test_terminal_url_null_base_returns_minus1(void)
{
	char out[256];

	ELA_ASSERT_INT_EQ(-1, ela_ws_build_terminal_url(NULL, "aa:bb", out, sizeof(out)));
}

static void test_terminal_url_null_mac_returns_minus1(void)
{
	char out[256];

	ELA_ASSERT_INT_EQ(-1, ela_ws_build_terminal_url("wss://h/api/", NULL, out, sizeof(out)));
}

static void test_terminal_url_trailing_slash_stripped(void)
{
	char out[256];

	ELA_ASSERT_INT_EQ(0, ela_ws_build_terminal_url("wss://ela.example/api/", "aa-bb", out, sizeof(out)));
	ELA_ASSERT_STR_EQ("wss://ela.example/api/terminal/aa-bb", out);
}

static void test_terminal_url_no_trailing_slash(void)
{
	char out[256];

	ELA_ASSERT_INT_EQ(0, ela_ws_build_terminal_url("wss://ela.example/api", "cc-dd", out, sizeof(out)));
	ELA_ASSERT_STR_EQ("wss://ela.example/api/terminal/cc-dd", out);
}

/* =========================================================================
 * ela_ws_build_handshake_request
 * ====================================================================== */

static void test_handshake_null_out_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_ws_build_handshake_request(NULL, 256, "host", 443, "/", 1, "tok", "key=="));
}

static void test_handshake_null_host_returns_minus1(void)
{
	char out[512];

	ELA_ASSERT_INT_EQ(-1, ela_ws_build_handshake_request(out, sizeof(out), NULL, 443, "/", 1, "tok", "key=="));
}

static void test_handshake_default_port_no_port_in_host_header(void)
{
	char req[512];

	ELA_ASSERT_TRUE(ela_ws_build_handshake_request(req, sizeof(req), "ela.example", 443, "/terminal/aa-bb", 1, "token123", "abc123==") > 0);
	ELA_ASSERT_TRUE(strstr(req, "GET /terminal/aa-bb HTTP/1.1\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(req, "Host: ela.example\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(req, "Authorization: Bearer token123\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(req, "Sec-WebSocket-Key: abc123==\r\n") != NULL);
}

static void test_handshake_non_default_port_in_host_header(void)
{
	char req[512];

	ELA_ASSERT_TRUE(ela_ws_build_handshake_request(req, sizeof(req), "ela.example", 9000, "/path", 0, NULL, "key==") > 0);
	ELA_ASSERT_TRUE(strstr(req, "Host: ela.example:9000\r\n") != NULL);
}

static void test_handshake_no_auth_omits_authorization_header(void)
{
	char req[512];

	ELA_ASSERT_TRUE(ela_ws_build_handshake_request(req, sizeof(req), "ela.example", 443, "/path", 1, NULL, "key==") > 0);
	ELA_ASSERT_TRUE(strstr(req, "Authorization:") == NULL);
}

/* =========================================================================
 * ela_is_ws_url
 * ====================================================================== */

static void test_is_ws_url_null_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_is_ws_url(NULL));
}

static void test_is_ws_url_empty_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_is_ws_url(""));
}

static void test_is_ws_url_ws_scheme_returns_true(void)
{
	ELA_ASSERT_TRUE(ela_is_ws_url("ws://ela.example/path"));
}

static void test_is_ws_url_wss_scheme_returns_true(void)
{
	ELA_ASSERT_TRUE(ela_is_ws_url("wss://ela.example/path"));
}

static void test_is_ws_url_http_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_is_ws_url("http://ela.example/path"));
}

static void test_is_ws_url_https_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_is_ws_url("https://ela.example/path"));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_ws_url_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* ela_ws_base64_encode */
		{ "base64/three_bytes_foo",          test_base64_three_bytes_foo },
		{ "base64/one_byte_double_padding",  test_base64_one_byte_has_double_padding },
		{ "base64/two_bytes_single_padding", test_base64_two_bytes_has_single_padding },
		{ "base64/empty_no_crash",           test_base64_empty_no_crash },
		/* ela_ws_parse_url */
		{ "parse_url/null_url",              test_parse_url_null_url_returns_minus1 },
		{ "parse_url/null_host",             test_parse_url_null_host_returns_minus1 },
		{ "parse_url/unknown_scheme",        test_parse_url_unknown_scheme_returns_minus1 },
		{ "parse_url/wss_defaults",          test_parse_url_wss_defaults },
		{ "parse_url/ws_default_port_80",    test_parse_url_ws_default_port_80 },
		{ "parse_url/explicit_port",         test_parse_url_explicit_port },
		{ "parse_url/no_path_is_slash",      test_parse_url_no_path_defaults_to_slash },
		/* ela_ws_build_terminal_url */
		{ "terminal_url/null_base",          test_terminal_url_null_base_returns_minus1 },
		{ "terminal_url/null_mac",           test_terminal_url_null_mac_returns_minus1 },
		{ "terminal_url/trailing_slash",     test_terminal_url_trailing_slash_stripped },
		{ "terminal_url/no_trailing_slash",  test_terminal_url_no_trailing_slash },
		/* ela_ws_build_handshake_request */
		{ "handshake/null_out",              test_handshake_null_out_returns_minus1 },
		{ "handshake/null_host",             test_handshake_null_host_returns_minus1 },
		{ "handshake/default_port",          test_handshake_default_port_no_port_in_host_header },
		{ "handshake/non_default_port",      test_handshake_non_default_port_in_host_header },
		{ "handshake/no_auth",               test_handshake_no_auth_omits_authorization_header },
		/* ela_is_ws_url */
		{ "is_ws_url/null",                  test_is_ws_url_null_returns_false },
		{ "is_ws_url/empty",                 test_is_ws_url_empty_returns_false },
		{ "is_ws_url/ws_scheme",             test_is_ws_url_ws_scheme_returns_true },
		{ "is_ws_url/wss_scheme",            test_is_ws_url_wss_scheme_returns_true },
		{ "is_ws_url/http_scheme",           test_is_ws_url_http_returns_false },
		{ "is_ws_url/https_scheme",          test_is_ws_url_https_returns_false },
	};

	return ela_run_test_suite("ws_url_util", cases, sizeof(cases) / sizeof(cases[0]));
}
