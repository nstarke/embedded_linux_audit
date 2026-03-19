// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/http_client_runtime_util.h"

#include <string.h>

static void test_http_client_body_policy_helpers(void)
{
	ELA_ASSERT_TRUE(ela_http_body_is_chunked("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"));
	ELA_ASSERT_FALSE(ela_http_body_is_chunked("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n"));
	ELA_ASSERT_INT_EQ(16, (int)ela_http_chunk_read_size(16, 4096));
	ELA_ASSERT_INT_EQ(4096, (int)ela_http_chunk_read_size(9000, 4096));
	ELA_ASSERT_INT_EQ(0, (int)ela_http_chunk_read_size(12, 0));
}

static void test_http_client_resolve_host_policy_helper(void)
{
	ELA_ASSERT_FALSE(ela_http_should_try_udp_resolve_host(NULL));
	ELA_ASSERT_FALSE(ela_http_should_try_udp_resolve_host(""));
	ELA_ASSERT_FALSE(ela_http_should_try_udp_resolve_host("192.168.1.20"));
	ELA_ASSERT_TRUE(ela_http_should_try_udp_resolve_host("ela.example"));
	ELA_ASSERT_TRUE(ela_http_should_try_udp_resolve_host("10.0.0"));
}

static void test_http_client_upload_mac_selection_helper(void)
{
	char mac[18];

	ELA_ASSERT_INT_EQ(0, ela_http_choose_upload_mac_address("02:11:22:33:44:55",
								 "06:11:22:33:44:55",
								 mac,
								 sizeof(mac)));
	ELA_ASSERT_STR_EQ("02:11:22:33:44:55", mac);

	ELA_ASSERT_INT_EQ(0, ela_http_choose_upload_mac_address("00:00:00:00:00:00",
								 "06:11:22:33:44:55",
								 mac,
								 sizeof(mac)));
	ELA_ASSERT_STR_EQ("06:11:22:33:44:55", mac);

	ELA_ASSERT_INT_EQ(0, ela_http_choose_upload_mac_address("bad",
								 NULL,
								 mac,
								 sizeof(mac)));
	ELA_ASSERT_STR_EQ("00:00:00:00:00:00", mac);
}

static void test_http_client_error_and_retry_policy_helpers(void)
{
	char errbuf[128];

	ELA_ASSERT_TRUE(ela_http_should_retry_with_next_api_key(401));
	ELA_ASSERT_FALSE(ela_http_should_retry_with_next_api_key(403));

	memset(errbuf, 0, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(0, ela_http_format_status_error(503, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("HTTP status 503", errbuf);

	memset(errbuf, 0, sizeof(errbuf));
	ELA_ASSERT_INT_EQ(0, ela_http_format_curl_transport_error("Couldn't resolve host name",
								      errbuf,
								      sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("curl perform failed: Couldn't resolve host name", errbuf);
}

int run_http_client_runtime_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "http_client_body_policy_helpers", test_http_client_body_policy_helpers },
		{ "http_client_resolve_host_policy_helper", test_http_client_resolve_host_policy_helper },
		{ "http_client_upload_mac_selection_helper", test_http_client_upload_mac_selection_helper },
		{ "http_client_error_and_retry_policy_helpers", test_http_client_error_and_retry_policy_helpers },
	};

	return ela_run_test_suite("http_client_runtime_util", cases, sizeof(cases) / sizeof(cases[0]));
}
