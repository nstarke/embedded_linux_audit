// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/str_util.h"

#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * append_text
 * ====================================================================== */

static void test_append_text_null_buf_returns_minus1(void)
{
	size_t len = 0, cap = 0;

	ELA_ASSERT_INT_EQ(-1, append_text(NULL, &len, &cap, "hello"));
}

static void test_append_text_null_len_returns_minus1(void)
{
	char *buf = NULL;
	size_t cap = 0;

	ELA_ASSERT_INT_EQ(-1, append_text(&buf, NULL, &cap, "hello"));
	free(buf);
}

static void test_append_text_null_cap_returns_minus1(void)
{
	char *buf = NULL;
	size_t len = 0;

	ELA_ASSERT_INT_EQ(-1, append_text(&buf, &len, NULL, "hello"));
	free(buf);
}

static void test_append_text_null_text_returns_minus1(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;

	ELA_ASSERT_INT_EQ(-1, append_text(&buf, &len, &cap, NULL));
	free(buf);
}

static void test_append_text_empty_string(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;

	ELA_ASSERT_INT_EQ(0, append_text(&buf, &len, &cap, ""));
	ELA_ASSERT_INT_EQ(0, (int)len);
	ELA_ASSERT_TRUE(buf != NULL);
	ELA_ASSERT_INT_EQ('\0', buf[0]);
	free(buf);
}

static void test_append_text_grows_and_concatenates(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;

	ELA_ASSERT_INT_EQ(0, append_text(&buf, &len, &cap, "hello"));
	ELA_ASSERT_INT_EQ(0, append_text(&buf, &len, &cap, " world"));
	ELA_ASSERT_INT_EQ(11, (int)len);
	ELA_ASSERT_TRUE(cap >= len + 1);
	ELA_ASSERT_STR_EQ("hello world", buf);
	free(buf);
}

static void test_append_text_three_parts(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;

	ELA_ASSERT_INT_EQ(0, append_text(&buf, &len, &cap, "a"));
	ELA_ASSERT_INT_EQ(0, append_text(&buf, &len, &cap, "b"));
	ELA_ASSERT_INT_EQ(0, append_text(&buf, &len, &cap, "c"));
	ELA_ASSERT_STR_EQ("abc", buf);
	free(buf);
}

/* =========================================================================
 * append_bytes
 * ====================================================================== */

static void test_append_bytes_null_buf_returns_minus1(void)
{
	size_t len = 0, cap = 0;

	ELA_ASSERT_INT_EQ(-1, append_bytes(NULL, &len, &cap, "x", 1));
}

static void test_append_bytes_null_data_nonzero_len_returns_minus1(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;

	ELA_ASSERT_INT_EQ(-1, append_bytes(&buf, &len, &cap, NULL, 1));
	free(buf);
}

static void test_append_bytes_null_data_zero_len_ok(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;

	/* NULL data with data_len=0 is explicitly permitted */
	ELA_ASSERT_INT_EQ(0, append_bytes(&buf, &len, &cap, NULL, 0));
	ELA_ASSERT_INT_EQ(0, (int)len);
	free(buf);
}

static void test_append_bytes_preserves_embedded_nul_and_terminates(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	const char payload[] = { 'A', '\0', 'B' };

	ELA_ASSERT_INT_EQ(0, append_bytes(&buf, &len, &cap, payload, sizeof(payload)));
	ELA_ASSERT_INT_EQ((int)sizeof(payload), (int)len);
	ELA_ASSERT_INT_EQ('A', (unsigned char)buf[0]);
	ELA_ASSERT_INT_EQ(0,   (unsigned char)buf[1]);
	ELA_ASSERT_INT_EQ('B', (unsigned char)buf[2]);
	ELA_ASSERT_INT_EQ(0,   (unsigned char)buf[3]);
	free(buf);
}

/* =========================================================================
 * url_percent_encode
 * ====================================================================== */

static void test_url_percent_encode_null_returns_null(void)
{
	ELA_ASSERT_TRUE(url_percent_encode(NULL) == NULL);
}

static void test_url_percent_encode_empty_returns_null(void)
{
	/* empty input: loop never runs, no allocation, returns NULL */
	ELA_ASSERT_TRUE(url_percent_encode("") == NULL);
}

static void test_url_percent_encode_escapes_reserved_bytes(void)
{
	char *encoded = url_percent_encode("a/b c?d=e&f");

	ELA_ASSERT_STR_EQ("a%2Fb%20c%3Fd%3De%26f", encoded);
	free(encoded);
}

static void test_url_percent_encode_keeps_unreserved_bytes(void)
{
	char *encoded = url_percent_encode("AZaz09-_.~");

	ELA_ASSERT_STR_EQ("AZaz09-_.~", encoded);
	free(encoded);
}

static void test_url_percent_encode_high_byte(void)
{
	/* 0xFF should become %FF */
	const char in[2] = { (char)0xFF, '\0' };
	char *encoded = url_percent_encode(in);

	ELA_ASSERT_TRUE(encoded != NULL);
	ELA_ASSERT_STR_EQ("%FF", encoded);
	free(encoded);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_str_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* append_text */
		{ "append_text/null_buf",              test_append_text_null_buf_returns_minus1 },
		{ "append_text/null_len",              test_append_text_null_len_returns_minus1 },
		{ "append_text/null_cap",              test_append_text_null_cap_returns_minus1 },
		{ "append_text/null_text",             test_append_text_null_text_returns_minus1 },
		{ "append_text/empty_string",          test_append_text_empty_string },
		{ "append_text/grows_and_concatenates", test_append_text_grows_and_concatenates },
		{ "append_text/three_parts",           test_append_text_three_parts },
		/* append_bytes */
		{ "append_bytes/null_buf",             test_append_bytes_null_buf_returns_minus1 },
		{ "append_bytes/null_data_nonzero",    test_append_bytes_null_data_nonzero_len_returns_minus1 },
		{ "append_bytes/null_data_zero_ok",    test_append_bytes_null_data_zero_len_ok },
		{ "append_bytes/embedded_nul",         test_append_bytes_preserves_embedded_nul_and_terminates },
		/* url_percent_encode */
		{ "url_encode/null_returns_null",      test_url_percent_encode_null_returns_null },
		{ "url_encode/empty",                  test_url_percent_encode_empty_returns_null },
		{ "url_encode/reserved_chars",         test_url_percent_encode_escapes_reserved_bytes },
		{ "url_encode/unreserved_chars",       test_url_percent_encode_keeps_unreserved_bytes },
		{ "url_encode/high_byte",              test_url_percent_encode_high_byte },
	};

	return ela_run_test_suite("str_util", cases, sizeof(cases) / sizeof(cases[0]));
}
