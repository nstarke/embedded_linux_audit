// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/http_uri_util.h"

#include <stdlib.h>

static void test_parse_http_uri_sets_defaults_and_path(void)
{
	struct parsed_http_uri parsed;

	ELA_ASSERT_INT_EQ(0, parse_http_uri("https://example.com/upload", &parsed));
	ELA_ASSERT_TRUE(parsed.https);
	ELA_ASSERT_STR_EQ("example.com", parsed.host);
	ELA_ASSERT_INT_EQ(443, parsed.port);
	ELA_ASSERT_STR_EQ("/upload", parsed.path);
}

static void test_parse_http_uri_accepts_explicit_port_and_empty_path(void)
{
	struct parsed_http_uri parsed;

	ELA_ASSERT_INT_EQ(0, parse_http_uri("http://user@example.com:8080", &parsed));
	ELA_ASSERT_FALSE(parsed.https);
	ELA_ASSERT_STR_EQ("example.com", parsed.host);
	ELA_ASSERT_INT_EQ(8080, parsed.port);
	ELA_ASSERT_STR_EQ("/", parsed.path);
}

static void test_normalize_default_port_adds_missing_port(void)
{
	char *normalized = ela_http_uri_normalize_default_port("https://ela.example/upload", 443);

	ELA_ASSERT_STR_EQ("https://ela.example:443/upload", normalized);
	free(normalized);
}

static void test_normalize_default_port_keeps_explicit_port(void)
{
	char *normalized = ela_http_uri_normalize_default_port("http://ela.example:8080/upload", 80);

	ELA_ASSERT_STR_EQ("http://ela.example:8080/upload", normalized);
	free(normalized);
}

static void test_parse_http_output_uri_splits_http_and_https(void)
{
	const char *out_http = NULL;
	const char *out_https = NULL;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_parse_http_output_uri("https://ela.example/upload",
						       &out_http, &out_https,
						       errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(out_http == NULL);
	ELA_ASSERT_STR_EQ("https://ela.example/upload", out_https);
}

static void test_parse_http_uri_host_handles_authority(void)
{
	char host[256];

	ELA_ASSERT_INT_EQ(0, ela_parse_http_uri_host("https://user@example.com:8443/upload", host, sizeof(host)));
	ELA_ASSERT_STR_EQ("example.com", host);
}

int run_http_uri_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "parse_http_uri_sets_defaults_and_path", test_parse_http_uri_sets_defaults_and_path },
		{ "parse_http_uri_accepts_explicit_port_and_empty_path", test_parse_http_uri_accepts_explicit_port_and_empty_path },
		{ "normalize_default_port_adds_missing_port", test_normalize_default_port_adds_missing_port },
		{ "normalize_default_port_keeps_explicit_port", test_normalize_default_port_keeps_explicit_port },
		{ "parse_http_output_uri_splits_http_and_https", test_parse_http_output_uri_splits_http_and_https },
		{ "parse_http_uri_host_handles_authority", test_parse_http_uri_host_handles_authority },
	};

	return ela_run_test_suite("http_uri_util", cases, sizeof(cases) / sizeof(cases[0]));
}
