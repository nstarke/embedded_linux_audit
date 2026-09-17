// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/output_buffer.h"

static void test_printf_appends_and_grows(void)
{
	struct output_buffer out = { 0 };
	char large[2049];

	memset(large, 'x', sizeof(large) - 1);
	large[sizeof(large) - 1] = '\0';
	ELA_ASSERT_INT_EQ(0, output_buffer_printf(&out, "%s:%d", "prefix", 42));
	ELA_ASSERT_STR_EQ("prefix:42", out.data);
	ELA_ASSERT_INT_EQ(0, output_buffer_printf(&out, "%s/%d", large, 7));
	ELA_ASSERT_INT_EQ(2059, (int)out.len);
	ELA_ASSERT_TRUE(memcmp(out.data + 9, large, 2048) == 0);
	ELA_ASSERT_STR_EQ("/7", out.data + 2057);
	free(out.data);
}

static void test_printf_keeps_embedded_nul(void)
{
	struct output_buffer out = { 0 };

	ELA_ASSERT_INT_EQ(0, output_buffer_printf(&out, "a%cb", 0));
	ELA_ASSERT_INT_EQ(3, (int)out.len);
	ELA_ASSERT_TRUE(memcmp(out.data, "a\0b\0", 4) == 0);
	ELA_ASSERT_INT_EQ(0, output_buffer_printf(&out, "%s", ""));
	ELA_ASSERT_INT_EQ(3, (int)out.len);
	free(out.data);
}

int run_output_buffer_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "printf/appends-and-grows", test_printf_appends_and_grows },
		{ "printf/embedded-nul", test_printf_keeps_embedded_nul },
	};

	return ela_run_test_suite("output_buffer", cases, sizeof(cases) / sizeof(cases[0]));
}
