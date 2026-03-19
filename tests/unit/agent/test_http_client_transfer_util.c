// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/http_client_transfer_util.h"

#include <string.h>

static void test_http_client_transfer_post_plan(void)
{
	struct ela_http_transfer_plan plan;
	char errbuf[128];

	memset(&plan, 0, sizeof(plan));
	ELA_ASSERT_INT_EQ(0, ela_http_prepare_post_plan("http://ela.example/upload",
							NULL,
							&plan,
							errbuf,
							sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_HTTP_TRANSPORT_HTTP, plan.transport);
	ELA_ASSERT_TRUE(strstr(plan.effective_uri, "http://ela.example:80/upload") != NULL);
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8", plan.content_type);
	ela_http_transfer_plan_cleanup(&plan);

	memset(&plan, 0, sizeof(plan));
	ELA_ASSERT_INT_EQ(0, ela_http_prepare_post_plan("https://ela.example/upload",
							"application/json",
							&plan,
							errbuf,
							sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_HTTP_TRANSPORT_HTTPS, plan.transport);
	ELA_ASSERT_TRUE(strstr(plan.effective_uri, "https://ela.example:443/upload") != NULL);
	ELA_ASSERT_STR_EQ("application/json", plan.content_type);
	ela_http_transfer_plan_cleanup(&plan);
}

static void test_http_client_transfer_plan_validation(void)
{
	struct ela_http_transfer_plan plan;
	char errbuf[128];

	memset(&plan, 0, sizeof(plan));
	ELA_ASSERT_INT_EQ(-1, ela_http_prepare_post_plan("", NULL, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("HTTP URI is empty", errbuf);

	memset(&plan, 0, sizeof(plan));
	ELA_ASSERT_INT_EQ(-1, ela_http_prepare_post_plan("ftp://ela.example/file",
							 NULL, &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "unsupported URI scheme") != NULL);

	memset(&plan, 0, sizeof(plan));
	ELA_ASSERT_INT_EQ(-1, ela_http_prepare_get_plan("http://ela.example/file",
							"", &plan, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("HTTP GET requires URI and output path", errbuf);
}

static void test_http_client_transfer_warn_policy(void)
{
	ELA_ASSERT_TRUE(ela_http_should_warn_unauthorized_status(401));
	ELA_ASSERT_FALSE(ela_http_should_warn_unauthorized_status(403));
}

int run_http_client_transfer_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "http_client_transfer_post_plan", test_http_client_transfer_post_plan },
		{ "http_client_transfer_plan_validation", test_http_client_transfer_plan_validation },
		{ "http_client_transfer_warn_policy", test_http_client_transfer_warn_policy },
	};

	return ela_run_test_suite("http_client_transfer_util", cases, sizeof(cases) / sizeof(cases[0]));
}
