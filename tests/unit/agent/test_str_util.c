// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/str_util.h"

#include <stdlib.h>

static void test_append_text_grows_and_concatenates(void)
{
	char *buf = NULL;
	size_t len = 0;
	size_t cap = 0;

	ELA_ASSERT_INT_EQ(0, append_text(&buf, &len, &cap, "hello"));
	ELA_ASSERT_INT_EQ(0, append_text(&buf, &len, &cap, " world"));
	ELA_ASSERT_INT_EQ(11, len);
	ELA_ASSERT_TRUE(cap >= len + 1);
	ELA_ASSERT_STR_EQ("hello world", buf);
	free(buf);
}

static void test_append_bytes_preserves_embedded_nul_and_terminates(void)
{
	char *buf = NULL;
	size_t len = 0;
	size_t cap = 0;
	const char payload[] = { 'A', '\0', 'B' };

	ELA_ASSERT_INT_EQ(0, append_bytes(&buf, &len, &cap, payload, sizeof(payload)));
	ELA_ASSERT_INT_EQ((int)sizeof(payload), (int)len);
	ELA_ASSERT_INT_EQ('A', (unsigned char)buf[0]);
	ELA_ASSERT_INT_EQ(0, (unsigned char)buf[1]);
	ELA_ASSERT_INT_EQ('B', (unsigned char)buf[2]);
	ELA_ASSERT_INT_EQ(0, (unsigned char)buf[3]);
	free(buf);
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

int run_str_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "append_text_grows_and_concatenates", test_append_text_grows_and_concatenates },
		{ "append_bytes_preserves_embedded_nul_and_terminates", test_append_bytes_preserves_embedded_nul_and_terminates },
		{ "url_percent_encode_escapes_reserved_bytes", test_url_percent_encode_escapes_reserved_bytes },
		{ "url_percent_encode_keeps_unreserved_bytes", test_url_percent_encode_keeps_unreserved_bytes },
	};

	return ela_run_test_suite("str_util", cases, sizeof(cases) / sizeof(cases[0]));
}
