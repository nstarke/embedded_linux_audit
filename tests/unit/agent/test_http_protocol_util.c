// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/http_protocol_util.h"

#include <stdlib.h>
#include <string.h>

static void test_http_header_helpers_parse_status_and_chunked_encoding(void)
{
	const char *headers = "HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: chunked\r\n\r\n";

	ELA_ASSERT_INT_EQ(206, ela_http_parse_status_code_from_headers(headers));
	ELA_ASSERT_TRUE(ela_http_headers_have_chunked_encoding(headers));
}

static void test_http_mac_helpers_validate_format(void)
{
	ELA_ASSERT_TRUE(ela_http_is_valid_mac_address_string("aa:bb:cc:dd:ee:ff"));
	ELA_ASSERT_FALSE(ela_http_is_valid_mac_address_string("aa-bb-cc-dd-ee-ff"));
	ELA_ASSERT_TRUE(ela_http_is_zero_mac_address_string("00:00:00:00:00:00"));
}

static void test_http_request_builder_emits_expected_headers(void)
{
	char *request = NULL;

	ELA_ASSERT_INT_EQ(0, ela_http_build_basic_request(&request, "POST", "ela.example", "/upload", 443, true,
						      "application/json", 12, "token123"));
	ELA_ASSERT_TRUE(request != NULL);
	ELA_ASSERT_TRUE(strstr(request, "POST /upload HTTP/1.1\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(request, "Host: ela.example\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(request, "Content-Type: application/json\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(request, "Content-Length: 12\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(request, "Authorization: Bearer token123\r\n") != NULL);
	free(request);
}

int run_http_protocol_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "http_header_helpers_parse_status_and_chunked_encoding", test_http_header_helpers_parse_status_and_chunked_encoding },
		{ "http_mac_helpers_validate_format", test_http_mac_helpers_validate_format },
		{ "http_request_builder_emits_expected_headers", test_http_request_builder_emits_expected_headers },
	};

	return ela_run_test_suite("http_protocol_util", cases, sizeof(cases) / sizeof(cases[0]));
}
