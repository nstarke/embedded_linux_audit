// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/http_uri_util.h"

#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * parse_http_uri
 * ====================================================================== */

static void test_parse_uri_null_uri_returns_minus1(void)
{
	struct parsed_http_uri p;

	ELA_ASSERT_INT_EQ(-1, parse_http_uri(NULL, &p));
}

static void test_parse_uri_null_parsed_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, parse_http_uri("https://example.com/", NULL));
}

static void test_parse_uri_no_scheme_returns_minus1(void)
{
	struct parsed_http_uri p;

	ELA_ASSERT_INT_EQ(-1, parse_http_uri("example.com/path", &p));
}

static void test_parse_uri_unknown_scheme_returns_minus1(void)
{
	struct parsed_http_uri p;

	ELA_ASSERT_INT_EQ(-1, parse_http_uri("ftp://example.com/path", &p));
}

static void test_parse_uri_ipv6_host_rejected(void)
{
	struct parsed_http_uri p;

	/* IPv6 bracket notation is not supported */
	ELA_ASSERT_INT_EQ(-1, parse_http_uri("http://[::1]/path", &p));
}

static void test_parse_uri_https_defaults(void)
{
	struct parsed_http_uri p;

	ELA_ASSERT_INT_EQ(0, parse_http_uri("https://example.com/upload", &p));
	ELA_ASSERT_TRUE(p.https);
	ELA_ASSERT_STR_EQ("example.com", p.host);
	ELA_ASSERT_INT_EQ(443, p.port);
	ELA_ASSERT_STR_EQ("/upload", p.path);
}

static void test_parse_uri_http_default_port_80(void)
{
	struct parsed_http_uri p;

	ELA_ASSERT_INT_EQ(0, parse_http_uri("http://example.com/path", &p));
	ELA_ASSERT_FALSE(p.https);
	ELA_ASSERT_INT_EQ(80, p.port);
}

static void test_parse_uri_explicit_port_and_empty_path(void)
{
	struct parsed_http_uri p;

	ELA_ASSERT_INT_EQ(0, parse_http_uri("http://user@example.com:8080", &p));
	ELA_ASSERT_FALSE(p.https);
	ELA_ASSERT_STR_EQ("example.com", p.host);
	ELA_ASSERT_INT_EQ(8080, p.port);
	ELA_ASSERT_STR_EQ("/", p.path);
}

static void test_parse_uri_no_path_defaults_to_slash(void)
{
	struct parsed_http_uri p;

	ELA_ASSERT_INT_EQ(0, parse_http_uri("https://example.com", &p));
	ELA_ASSERT_STR_EQ("/", p.path);
}

/* =========================================================================
 * ela_http_uri_normalize_default_port
 * ====================================================================== */

static void test_normalize_port_null_returns_null(void)
{
	ELA_ASSERT_TRUE(ela_http_uri_normalize_default_port(NULL, 443) == NULL);
}

static void test_normalize_port_empty_returns_null(void)
{
	ELA_ASSERT_TRUE(ela_http_uri_normalize_default_port("", 443) == NULL);
}

static void test_normalize_port_adds_missing_port(void)
{
	char *out = ela_http_uri_normalize_default_port("https://ela.example/upload", 443);

	ELA_ASSERT_STR_EQ("https://ela.example:443/upload", out);
	free(out);
}

static void test_normalize_port_keeps_existing_explicit_port(void)
{
	char *out = ela_http_uri_normalize_default_port("http://ela.example:8080/upload", 80);

	ELA_ASSERT_STR_EQ("http://ela.example:8080/upload", out);
	free(out);
}

static void test_normalize_port_no_scheme_passthrough(void)
{
	char *out = ela_http_uri_normalize_default_port("not-a-uri", 80);

	ELA_ASSERT_STR_EQ("not-a-uri", out);
	free(out);
}

static void test_normalize_port_uri_with_no_path(void)
{
	char *out = ela_http_uri_normalize_default_port("https://host.example", 443);

	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, ":443") != NULL);
	free(out);
}

/* =========================================================================
 * ela_parse_http_output_uri
 * ====================================================================== */

static void test_output_uri_null_returns_ok(void)
{
	const char *http_out = NULL, *https_out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_parse_http_output_uri(NULL, &http_out, &https_out, NULL, 0));
	ELA_ASSERT_TRUE(http_out == NULL);
	ELA_ASSERT_TRUE(https_out == NULL);
}

static void test_output_uri_empty_returns_ok(void)
{
	const char *http_out = NULL, *https_out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_parse_http_output_uri("", &http_out, &https_out, NULL, 0));
	ELA_ASSERT_TRUE(http_out == NULL);
	ELA_ASSERT_TRUE(https_out == NULL);
}

static void test_output_uri_http_sets_http_out(void)
{
	const char *uri = "http://ela.example/upload";
	const char *http_out = NULL, *https_out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_parse_http_output_uri(uri, &http_out, &https_out, NULL, 0));
	ELA_ASSERT_TRUE(http_out == uri);
	ELA_ASSERT_TRUE(https_out == NULL);
}

static void test_output_uri_https_sets_https_out(void)
{
	const char *uri = "https://ela.example/upload";
	const char *http_out = NULL, *https_out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_parse_http_output_uri(uri, &http_out, &https_out, NULL, 0));
	ELA_ASSERT_TRUE(http_out == NULL);
	ELA_ASSERT_TRUE(https_out == uri);
}

static void test_output_uri_invalid_scheme_returns_minus1(void)
{
	const char *http_out = NULL, *https_out = NULL;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(-1, ela_parse_http_output_uri("ftp://ela.example/up",
							&http_out, &https_out,
							errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(errbuf[0] != '\0');
}

/* =========================================================================
 * ela_parse_http_uri_host
 * ====================================================================== */

static void test_parse_host_null_uri_returns_minus1(void)
{
	char host[64];

	ELA_ASSERT_INT_EQ(-1, ela_parse_http_uri_host(NULL, host, sizeof(host)));
}

static void test_parse_host_null_buf_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_parse_http_uri_host("https://example.com/", NULL, 64));
}

static void test_parse_host_small_buf_returns_minus1(void)
{
	char host[1];

	ELA_ASSERT_INT_EQ(-1, ela_parse_http_uri_host("https://example.com/", host, 1));
}

static void test_parse_host_no_scheme_returns_minus1(void)
{
	char host[64];

	ELA_ASSERT_INT_EQ(-1, ela_parse_http_uri_host("example.com/path", host, sizeof(host)));
}

static void test_parse_host_simple(void)
{
	char host[64];

	ELA_ASSERT_INT_EQ(0, ela_parse_http_uri_host("https://example.com/path", host, sizeof(host)));
	ELA_ASSERT_STR_EQ("example.com", host);
}

static void test_parse_host_with_userinfo_and_port(void)
{
	char host[64];

	ELA_ASSERT_INT_EQ(0, ela_parse_http_uri_host("https://user@example.com:8443/upload",
						      host, sizeof(host)));
	ELA_ASSERT_STR_EQ("example.com", host);
}

static void test_parse_host_ipv6(void)
{
	char host[64];

	ELA_ASSERT_INT_EQ(0, ela_parse_http_uri_host("https://[::1]/path", host, sizeof(host)));
	ELA_ASSERT_STR_EQ("::1", host);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_http_uri_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* parse_http_uri */
		{ "parse_uri/null_uri",             test_parse_uri_null_uri_returns_minus1 },
		{ "parse_uri/null_parsed",          test_parse_uri_null_parsed_returns_minus1 },
		{ "parse_uri/no_scheme",            test_parse_uri_no_scheme_returns_minus1 },
		{ "parse_uri/unknown_scheme",       test_parse_uri_unknown_scheme_returns_minus1 },
		{ "parse_uri/ipv6_rejected",        test_parse_uri_ipv6_host_rejected },
		{ "parse_uri/https_defaults",       test_parse_uri_https_defaults },
		{ "parse_uri/http_default_80",      test_parse_uri_http_default_port_80 },
		{ "parse_uri/explicit_port",        test_parse_uri_explicit_port_and_empty_path },
		{ "parse_uri/no_path_is_slash",     test_parse_uri_no_path_defaults_to_slash },
		/* normalize_default_port */
		{ "normalize_port/null",            test_normalize_port_null_returns_null },
		{ "normalize_port/empty",           test_normalize_port_empty_returns_null },
		{ "normalize_port/adds_port",       test_normalize_port_adds_missing_port },
		{ "normalize_port/keeps_port",      test_normalize_port_keeps_existing_explicit_port },
		{ "normalize_port/no_scheme",       test_normalize_port_no_scheme_passthrough },
		{ "normalize_port/no_path",         test_normalize_port_uri_with_no_path },
		/* parse_http_output_uri */
		{ "output_uri/null",                test_output_uri_null_returns_ok },
		{ "output_uri/empty",               test_output_uri_empty_returns_ok },
		{ "output_uri/http",                test_output_uri_http_sets_http_out },
		{ "output_uri/https",               test_output_uri_https_sets_https_out },
		{ "output_uri/invalid",             test_output_uri_invalid_scheme_returns_minus1 },
		/* parse_http_uri_host */
		{ "parse_host/null_uri",            test_parse_host_null_uri_returns_minus1 },
		{ "parse_host/null_buf",            test_parse_host_null_buf_returns_minus1 },
		{ "parse_host/small_buf",           test_parse_host_small_buf_returns_minus1 },
		{ "parse_host/no_scheme",           test_parse_host_no_scheme_returns_minus1 },
		{ "parse_host/simple",              test_parse_host_simple },
		{ "parse_host/userinfo_and_port",   test_parse_host_with_userinfo_and_port },
		{ "parse_host/ipv6",                test_parse_host_ipv6 },
	};

	return ela_run_test_suite("http_uri_util", cases, sizeof(cases) / sizeof(cases[0]));
}
