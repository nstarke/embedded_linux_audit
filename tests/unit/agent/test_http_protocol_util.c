// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/http_protocol_util.h"

#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * ela_http_parse_status_code_from_headers
 * ====================================================================== */

static void test_status_null_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_http_parse_status_code_from_headers(NULL));
}

static void test_status_bad_format_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_http_parse_status_code_from_headers("garbage"));
	ELA_ASSERT_INT_EQ(-1, ela_http_parse_status_code_from_headers(""));
}

static void test_status_200(void)
{
	ELA_ASSERT_INT_EQ(200, ela_http_parse_status_code_from_headers("HTTP/1.1 200 OK\r\n\r\n"));
}

static void test_status_206(void)
{
	ELA_ASSERT_INT_EQ(206,
		ela_http_parse_status_code_from_headers(
			"HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: chunked\r\n\r\n"));
}

static void test_status_404(void)
{
	ELA_ASSERT_INT_EQ(404, ela_http_parse_status_code_from_headers("HTTP/1.0 404 Not Found\r\n\r\n"));
}

static void test_status_500(void)
{
	ELA_ASSERT_INT_EQ(500,
		ela_http_parse_status_code_from_headers("HTTP/1.1 500 Internal Server Error\r\n\r\n"));
}

/* =========================================================================
 * ela_http_headers_have_chunked_encoding
 * ====================================================================== */

static void test_chunked_null_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_http_headers_have_chunked_encoding(NULL));
}

static void test_chunked_not_present_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_http_headers_have_chunked_encoding(
		"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"));
}

static void test_chunked_present_returns_true(void)
{
	ELA_ASSERT_TRUE(ela_http_headers_have_chunked_encoding(
		"HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: chunked\r\n\r\n"));
}

/* =========================================================================
 * ela_http_is_valid_mac_address_string
 * ====================================================================== */

static void test_mac_null_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_http_is_valid_mac_address_string(NULL));
}

static void test_mac_lowercase_valid(void)
{
	ELA_ASSERT_TRUE(ela_http_is_valid_mac_address_string("aa:bb:cc:dd:ee:ff"));
}

static void test_mac_uppercase_valid(void)
{
	ELA_ASSERT_TRUE(ela_http_is_valid_mac_address_string("AA:BB:CC:DD:EE:FF"));
}

static void test_mac_mixed_case_valid(void)
{
	ELA_ASSERT_TRUE(ela_http_is_valid_mac_address_string("0A:1b:2C:3d:4E:5f"));
}

static void test_mac_wrong_separator_invalid(void)
{
	ELA_ASSERT_FALSE(ela_http_is_valid_mac_address_string("aa-bb-cc-dd-ee-ff"));
}

static void test_mac_too_short_invalid(void)
{
	ELA_ASSERT_FALSE(ela_http_is_valid_mac_address_string("aa:bb:cc:dd:ee"));
}

static void test_mac_trailing_chars_invalid(void)
{
	ELA_ASSERT_FALSE(ela_http_is_valid_mac_address_string("aa:bb:cc:dd:ee:ff:00"));
}

static void test_mac_non_hex_invalid(void)
{
	ELA_ASSERT_FALSE(ela_http_is_valid_mac_address_string("zz:bb:cc:dd:ee:ff"));
}

/* =========================================================================
 * ela_http_is_zero_mac_address_string
 * ====================================================================== */

static void test_zero_mac_null_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_http_is_zero_mac_address_string(NULL));
}

static void test_zero_mac_all_zeros_returns_true(void)
{
	ELA_ASSERT_TRUE(ela_http_is_zero_mac_address_string("00:00:00:00:00:00"));
}

static void test_zero_mac_nonzero_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_http_is_zero_mac_address_string("00:00:00:00:00:01"));
	ELA_ASSERT_FALSE(ela_http_is_zero_mac_address_string("aa:bb:cc:dd:ee:ff"));
}

/* =========================================================================
 * ela_http_build_basic_request
 * ====================================================================== */

static void test_build_request_null_out_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_http_build_basic_request(NULL, "POST", "host", "/", 443, true,
							   NULL, 0, NULL));
}

static void test_build_request_null_method_returns_minus1(void)
{
	char *r = NULL;

	ELA_ASSERT_INT_EQ(-1, ela_http_build_basic_request(&r, NULL, "host", "/", 443, true,
							   NULL, 0, NULL));
	free(r);
}

static void test_build_request_full_with_auth_and_content_type(void)
{
	char *r = NULL;

	ELA_ASSERT_INT_EQ(0, ela_http_build_basic_request(&r, "POST", "ela.example", "/upload",
							  443, true, "application/json", 12, "token123"));
	ELA_ASSERT_TRUE(r != NULL);
	ELA_ASSERT_TRUE(strstr(r, "POST /upload HTTP/1.1\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(r, "Host: ela.example\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(r, "Content-Type: application/json\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(r, "Content-Length: 12\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(r, "Authorization: Bearer token123\r\n") != NULL);
	free(r);
}

static void test_build_request_no_content_type(void)
{
	char *r = NULL;

	ELA_ASSERT_INT_EQ(0, ela_http_build_basic_request(&r, "GET", "host", "/path",
							  80, false, NULL, 0, NULL));
	ELA_ASSERT_TRUE(r != NULL);
	ELA_ASSERT_TRUE(strstr(r, "Content-Type:") == NULL);
	ELA_ASSERT_TRUE(strstr(r, "Authorization:") == NULL);
	free(r);
}

static void test_build_request_non_default_port_in_host_header(void)
{
	char *r = NULL;

	/* HTTPS on non-443 port: Host header must include the port */
	ELA_ASSERT_INT_EQ(0, ela_http_build_basic_request(&r, "POST", "ela.example", "/up",
							  8443, true, NULL, 0, NULL));
	ELA_ASSERT_TRUE(r != NULL);
	ELA_ASSERT_TRUE(strstr(r, "Host: ela.example:8443\r\n") != NULL);
	free(r);
}

static void test_build_request_default_port_omitted_from_host_header(void)
{
	char *r = NULL;

	/* HTTP on port 80: Host header should NOT include the port */
	ELA_ASSERT_INT_EQ(0, ela_http_build_basic_request(&r, "GET", "ela.example", "/",
							  80, false, NULL, 0, NULL));
	ELA_ASSERT_TRUE(r != NULL);
	ELA_ASSERT_TRUE(strstr(r, "Host: ela.example\r\n") != NULL);
	free(r);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_http_protocol_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* status code parsing */
		{ "status/null",                   test_status_null_returns_minus1 },
		{ "status/bad_format",             test_status_bad_format_returns_minus1 },
		{ "status/200",                    test_status_200 },
		{ "status/206",                    test_status_206 },
		{ "status/404",                    test_status_404 },
		{ "status/500",                    test_status_500 },
		/* chunked encoding */
		{ "chunked/null",                  test_chunked_null_returns_false },
		{ "chunked/not_present",           test_chunked_not_present_returns_false },
		{ "chunked/present",               test_chunked_present_returns_true },
		/* MAC address validation */
		{ "mac/null",                      test_mac_null_returns_false },
		{ "mac/lowercase_valid",           test_mac_lowercase_valid },
		{ "mac/uppercase_valid",           test_mac_uppercase_valid },
		{ "mac/mixed_case_valid",          test_mac_mixed_case_valid },
		{ "mac/wrong_sep",                 test_mac_wrong_separator_invalid },
		{ "mac/too_short",                 test_mac_too_short_invalid },
		{ "mac/trailing_chars",            test_mac_trailing_chars_invalid },
		{ "mac/non_hex",                   test_mac_non_hex_invalid },
		/* zero MAC */
		{ "zero_mac/null",                 test_zero_mac_null_returns_false },
		{ "zero_mac/all_zeros",            test_zero_mac_all_zeros_returns_true },
		{ "zero_mac/nonzero",              test_zero_mac_nonzero_returns_false },
		/* request builder */
		{ "build/null_out",                test_build_request_null_out_returns_minus1 },
		{ "build/null_method",             test_build_request_null_method_returns_minus1 },
		{ "build/full_request",            test_build_request_full_with_auth_and_content_type },
		{ "build/no_content_type_or_auth", test_build_request_no_content_type },
		{ "build/non_default_port",        test_build_request_non_default_port_in_host_header },
		{ "build/default_port_omitted",    test_build_request_default_port_omitted_from_host_header },
	};

	return ela_run_test_suite("http_protocol_util", cases, sizeof(cases) / sizeof(cases[0]));
}
