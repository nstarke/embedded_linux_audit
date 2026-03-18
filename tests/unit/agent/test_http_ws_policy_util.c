// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/http_ws_policy_util.h"

static void test_http_status_and_backend_policy_helpers(void)
{
	ELA_ASSERT_TRUE(ela_http_status_is_success(200));
	ELA_ASSERT_TRUE(ela_http_status_is_success(299));
	ELA_ASSERT_FALSE(ela_http_status_is_success(404));
	ELA_ASSERT_INT_EQ(ELA_HTTP_HTTPS_BACKEND_WOLFSSL, ela_http_choose_https_backend(true));
	ELA_ASSERT_INT_EQ(ELA_HTTP_HTTPS_BACKEND_OPENSSL, ela_http_choose_https_backend(false));
}

static void test_ws_keepalive_policy_helper(void)
{
	ELA_ASSERT_FALSE(ela_ws_should_send_keepalive(100, 90, 25));
	ELA_ASSERT_TRUE(ela_ws_should_send_keepalive(125, 100, 25));
}

int run_http_ws_policy_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "http_status_and_backend_policy_helpers", test_http_status_and_backend_policy_helpers },
		{ "ws_keepalive_policy_helper", test_ws_keepalive_policy_helper },
	};

	return ela_run_test_suite("http_ws_policy_util", cases, sizeof(cases) / sizeof(cases[0]));
}
