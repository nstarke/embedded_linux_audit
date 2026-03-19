// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/tpm2_output_format_util.h"

#include <stdlib.h>

static void test_tpm2_output_format_validation_and_content_type(void)
{
	ELA_ASSERT_TRUE(ela_tpm2_is_valid_output_format("txt"));
	ELA_ASSERT_TRUE(ela_tpm2_is_valid_output_format("csv"));
	ELA_ASSERT_TRUE(ela_tpm2_is_valid_output_format("json"));
	ELA_ASSERT_FALSE(ela_tpm2_is_valid_output_format("xml"));

	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8", ela_tpm2_output_content_type("txt"));
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8", ela_tpm2_output_content_type("csv"));
	ELA_ASSERT_STR_EQ("application/json; charset=utf-8", ela_tpm2_output_content_type("json"));
}

static void test_tpm2_kv_formatter_renders_supported_formats(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "txt", "bank", "sha256"));
	ELA_ASSERT_STR_EQ("bank: sha256\n", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "csv", "bank", "sha256"));
	ELA_ASSERT_STR_EQ("\"bank\",\"sha256\"\n", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "json", "bank", "sha256"));
	ELA_ASSERT_STR_EQ("{\"key\":\"bank\",\"value\":\"sha256\"}\n", out.data);
	free(out.data);
}

int run_tpm2_output_format_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "tpm2_output_format_validation_and_content_type", test_tpm2_output_format_validation_and_content_type },
		{ "tpm2_kv_formatter_renders_supported_formats", test_tpm2_kv_formatter_renders_supported_formats },
	};

	return ela_run_test_suite("tpm2_output_format_util", cases, sizeof(cases) / sizeof(cases[0]));
}
