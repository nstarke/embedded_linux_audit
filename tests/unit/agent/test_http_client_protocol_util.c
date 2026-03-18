// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/http_client_protocol_util.h"

#include <stdlib.h>
#include <string.h>

static void test_http_client_parse_response_headers_helper(void)
{
	const char *resp = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\nbody";
	size_t header_len = 0;
	int status = 0;

	ELA_ASSERT_INT_EQ(0, ela_http_parse_response_headers(resp, strlen(resp), &status, &header_len));
	ELA_ASSERT_INT_EQ(204, status);
	ELA_ASSERT_INT_EQ((int)strlen("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"), (int)header_len);

	ELA_ASSERT_INT_EQ(1, ela_http_parse_response_headers("HTTP/1.1 200 OK\r\nConnection: close\r\n",
							      strlen("HTTP/1.1 200 OK\r\nConnection: close\r\n"),
							      &status, &header_len));
	ELA_ASSERT_INT_EQ(-1, ela_http_parse_response_headers("garbage\r\n\r\n", strlen("garbage\r\n\r\n"),
							       &status, &header_len));
}

static void test_http_client_build_request_helpers(void)
{
	char *request = NULL;
	size_t request_len = 0;
	static const uint8_t body[] = "abc";

	ELA_ASSERT_INT_EQ(0, ela_http_build_get_request(&request, &request_len, "/api/v1/ping", "ela.example"));
	ELA_ASSERT_STR_EQ("GET /api/v1/ping HTTP/1.1\r\nHost: ela.example\r\nConnection: close\r\n\r\n", request);
	free(request);
	request = NULL;

	ELA_ASSERT_INT_EQ(0, ela_http_build_post_request(&request,
							 &request_len,
							 "/upload",
							 "ela.example",
							 "text/plain",
							 sizeof(body) - 1,
							 "token123",
							 body,
							 sizeof(body) - 1));
	ELA_ASSERT_TRUE(strstr(request, "POST /upload HTTP/1.1\r\nHost: ela.example\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(request, "Authorization: Bearer token123\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(request, "Content-Length: 3\r\n") != NULL);
	ELA_ASSERT_TRUE(request_len >= 3);
	ELA_ASSERT_TRUE(memcmp(request + request_len - 3, "abc", 3) == 0);
	free(request);
}

int run_http_client_protocol_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "http_client_parse_response_headers_helper", test_http_client_parse_response_headers_helper },
		{ "http_client_build_request_helpers", test_http_client_build_request_helpers },
	};

	return ela_run_test_suite("http_client_protocol_util", cases, sizeof(cases) / sizeof(cases[0]));
}
