// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/tpm2_output_format_util.h"

#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * ela_tpm2_is_valid_output_format
 * ---------------------------------------------------------------------- */

static void test_is_valid_format_null(void)
{
	ELA_ASSERT_FALSE(ela_tpm2_is_valid_output_format(NULL));
}

static void test_is_valid_format_empty(void)
{
	ELA_ASSERT_FALSE(ela_tpm2_is_valid_output_format(""));
}

static void test_is_valid_format_valid(void)
{
	ELA_ASSERT_TRUE(ela_tpm2_is_valid_output_format("txt"));
	ELA_ASSERT_TRUE(ela_tpm2_is_valid_output_format("csv"));
	ELA_ASSERT_TRUE(ela_tpm2_is_valid_output_format("json"));
}

static void test_is_valid_format_invalid(void)
{
	ELA_ASSERT_FALSE(ela_tpm2_is_valid_output_format("xml"));
	ELA_ASSERT_FALSE(ela_tpm2_is_valid_output_format("text"));
	ELA_ASSERT_FALSE(ela_tpm2_is_valid_output_format("TXT"));
	ELA_ASSERT_FALSE(ela_tpm2_is_valid_output_format("CSV"));
	ELA_ASSERT_FALSE(ela_tpm2_is_valid_output_format("JSON"));
	ELA_ASSERT_FALSE(ela_tpm2_is_valid_output_format("yaml"));
}

/* -------------------------------------------------------------------------
 * ela_tpm2_output_content_type
 * ---------------------------------------------------------------------- */

static void test_content_type_txt(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_tpm2_output_content_type("txt"));
}

static void test_content_type_csv(void)
{
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8",
			  ela_tpm2_output_content_type("csv"));
}

static void test_content_type_json(void)
{
	ELA_ASSERT_STR_EQ("application/json; charset=utf-8",
			  ela_tpm2_output_content_type("json"));
}

static void test_content_type_null_returns_default(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_tpm2_output_content_type(NULL));
}

static void test_content_type_unknown_returns_default(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_tpm2_output_content_type("xml"));
}

/* -------------------------------------------------------------------------
 * ela_tpm2_format_kv_record
 * ---------------------------------------------------------------------- */

static void test_format_kv_null_buf(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_format_kv_record(NULL, "txt", "k", "v"));
}

static void test_format_kv_null_key(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_format_kv_record(&out, "txt", NULL, "v"));
	free(out.data);
}

static void test_format_kv_null_value(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_format_kv_record(&out, "txt", "k", NULL));
	free(out.data);
}

static void test_format_kv_null_format(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_format_kv_record(&out, NULL, "k", "v"));
	free(out.data);
}

static void test_format_kv_invalid_format(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_format_kv_record(&out, "xml", "k", "v"));
	free(out.data);
}

static void test_format_kv_txt(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "txt", "bank", "sha256"));
	ELA_ASSERT_STR_EQ("bank: sha256\n", out.data);
	free(out.data);
}

static void test_format_kv_txt_multiple_accumulate(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "txt", "key1", "val1"));
	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "txt", "key2", "val2"));
	ELA_ASSERT_TRUE(strstr(out.data, "key1: val1\n") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "key2: val2\n") != NULL);
	free(out.data);
}

static void test_format_kv_txt_empty_key_and_value(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "txt", "", ""));
	ELA_ASSERT_STR_EQ(": \n", out.data);
	free(out.data);
}

static void test_format_kv_csv(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "csv", "bank", "sha256"));
	ELA_ASSERT_STR_EQ("\"bank\",\"sha256\"\n", out.data);
	free(out.data);
}

static void test_format_kv_csv_value_with_comma(void)
{
	struct output_buffer out = {0};

	/* A comma inside a CSV field should be quoted */
	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "csv", "k", "a,b"));
	ELA_ASSERT_TRUE(out.data != NULL);
	/* The value "a,b" must appear inside quotes */
	ELA_ASSERT_TRUE(strstr(out.data, "\"a,b\"") != NULL);
	free(out.data);
}

static void test_format_kv_csv_value_with_quote(void)
{
	struct output_buffer out = {0};

	/* A double-quote inside a CSV field must be escaped as "" */
	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "csv", "k", "say \"hi\""));
	ELA_ASSERT_TRUE(out.data != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "\"\"") != NULL);
	free(out.data);
}

static void test_format_kv_json(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "json", "bank", "sha256"));
	ELA_ASSERT_STR_EQ("{\"key\":\"bank\",\"value\":\"sha256\"}\n", out.data);
	free(out.data);
}

static void test_format_kv_json_multiple_accumulate(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "json", "pcr0", "aabbcc"));
	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "json", "pcr1", "ddeeff"));
	ELA_ASSERT_TRUE(strstr(out.data, "\"key\":\"pcr0\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "\"key\":\"pcr1\"") != NULL);
	free(out.data);
}

static void test_format_kv_csv_multiple_accumulate(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "csv", "key1", "val1"));
	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "csv", "key2", "val2"));
	ELA_ASSERT_TRUE(strstr(out.data, "\"key1\",\"val1\"\n") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "\"key2\",\"val2\"\n") != NULL);
	free(out.data);
}

static void test_format_kv_hex_value_preserved(void)
{
	struct output_buffer out = {0};

	/* Hex values like "0x000b" should pass through unchanged in txt */
	ELA_ASSERT_INT_EQ(0, ela_tpm2_format_kv_record(&out, "txt", "0x000b", "0x00000010"));
	ELA_ASSERT_STR_EQ("0x000b: 0x00000010\n", out.data);
	free(out.data);
}

int run_tpm2_output_format_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* is_valid_output_format */
		{ "is_valid_format_null",              test_is_valid_format_null },
		{ "is_valid_format_empty",             test_is_valid_format_empty },
		{ "is_valid_format_valid",             test_is_valid_format_valid },
		{ "is_valid_format_invalid",           test_is_valid_format_invalid },
		/* output_content_type */
		{ "content_type_txt",                  test_content_type_txt },
		{ "content_type_csv",                  test_content_type_csv },
		{ "content_type_json",                 test_content_type_json },
		{ "content_type_null_default",         test_content_type_null_returns_default },
		{ "content_type_unknown_default",      test_content_type_unknown_returns_default },
		/* format_kv_record */
		{ "format_kv_null_buf",                test_format_kv_null_buf },
		{ "format_kv_null_key",                test_format_kv_null_key },
		{ "format_kv_null_value",              test_format_kv_null_value },
		{ "format_kv_null_format",             test_format_kv_null_format },
		{ "format_kv_invalid_format",          test_format_kv_invalid_format },
		{ "format_kv_txt",                     test_format_kv_txt },
		{ "format_kv_txt_multiple",            test_format_kv_txt_multiple_accumulate },
		{ "format_kv_txt_empty_key_value",     test_format_kv_txt_empty_key_and_value },
		{ "format_kv_csv",                     test_format_kv_csv },
		{ "format_kv_csv_comma_in_value",      test_format_kv_csv_value_with_comma },
		{ "format_kv_csv_quote_in_value",      test_format_kv_csv_value_with_quote },
		{ "format_kv_json",                    test_format_kv_json },
		{ "format_kv_json_multiple",           test_format_kv_json_multiple_accumulate },
		{ "format_kv_csv_multiple",            test_format_kv_csv_multiple_accumulate },
		{ "format_kv_hex_value_preserved",     test_format_kv_hex_value_preserved },
	};

	return ela_run_test_suite("tpm2_output_format_util", cases, sizeof(cases) / sizeof(cases[0]));
}
