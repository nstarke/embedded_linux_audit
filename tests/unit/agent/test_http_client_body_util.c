// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/http_client_body_util.h"

#include <stdlib.h>
#include <string.h>

static void test_http_client_identity_get_request_helper(void)
{
	char *request = NULL;
	size_t request_len = 0;

	ELA_ASSERT_INT_EQ(0, ela_http_build_identity_get_request(&request, &request_len, "/firmware.bin", "ela.example"));
	ELA_ASSERT_TRUE(strstr(request, "GET /firmware.bin HTTP/1.1\r\nHost: ela.example\r\n") != NULL);
	ELA_ASSERT_TRUE(strstr(request, "Accept-Encoding: identity\r\n\r\n") != NULL);
	free(request);
}

static void test_http_client_chunk_size_parser(void)
{
	unsigned long chunk_len = 0;

	ELA_ASSERT_INT_EQ(0, ela_http_parse_chunk_size_line("1a\r\n", &chunk_len));
	ELA_ASSERT_INT_EQ(0x1a, (int)chunk_len);
	ELA_ASSERT_INT_EQ(0, ela_http_parse_chunk_size_line("2F;ext=value\r\n", &chunk_len));
	ELA_ASSERT_INT_EQ(0x2f, (int)chunk_len);
	ELA_ASSERT_INT_EQ(-1, ela_http_parse_chunk_size_line("xyz\r\n", &chunk_len));
}

int run_http_client_body_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "http_client_identity_get_request_helper", test_http_client_identity_get_request_helper },
		{ "http_client_chunk_size_parser", test_http_client_chunk_size_parser },
	};

	return ela_run_test_suite("http_client_body_util", cases, sizeof(cases) / sizeof(cases[0]));
}
