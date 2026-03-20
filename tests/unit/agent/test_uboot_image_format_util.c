// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/image/uboot_image_format_util.h"

/* =========================================================================
 * ela_uboot_image_detect_output_format
 * ====================================================================== */

static void test_detect_null_returns_txt(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_TXT,
			  ela_uboot_image_detect_output_format(NULL));
}

static void test_detect_empty_returns_txt(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_TXT,
			  ela_uboot_image_detect_output_format(""));
}

static void test_detect_txt_explicit(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_TXT,
			  ela_uboot_image_detect_output_format("txt"));
}

static void test_detect_csv(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_CSV,
			  ela_uboot_image_detect_output_format("csv"));
}

static void test_detect_json(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_JSON,
			  ela_uboot_image_detect_output_format("json"));
}

static void test_detect_unknown_falls_back_to_txt(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_TXT,
			  ela_uboot_image_detect_output_format("xml"));
}

/* =========================================================================
 * ela_uboot_image_http_content_type
 * ====================================================================== */

static void test_content_type_txt(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_uboot_image_http_content_type(FW_OUTPUT_TXT));
}

static void test_content_type_csv(void)
{
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8",
			  ela_uboot_image_http_content_type(FW_OUTPUT_CSV));
}

static void test_content_type_json(void)
{
	ELA_ASSERT_STR_EQ("application/x-ndjson; charset=utf-8",
			  ela_uboot_image_http_content_type(FW_OUTPUT_JSON));
}

static void test_content_type_unknown_returns_plain(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_uboot_image_http_content_type(999));
}

/* =========================================================================
 * ela_uboot_image_align_up_4
 * ====================================================================== */

static void test_align_zero(void)
{
	ELA_ASSERT_INT_EQ(0, (int)ela_uboot_image_align_up_4(0));
}

static void test_align_one(void)
{
	ELA_ASSERT_INT_EQ(4, (int)ela_uboot_image_align_up_4(1));
}

static void test_align_already_aligned(void)
{
	ELA_ASSERT_INT_EQ(4, (int)ela_uboot_image_align_up_4(4));
}

static void test_align_five(void)
{
	ELA_ASSERT_INT_EQ(8, (int)ela_uboot_image_align_up_4(5));
}

static void test_align_seven(void)
{
	ELA_ASSERT_INT_EQ(8, (int)ela_uboot_image_align_up_4(7));
}

static void test_align_eight(void)
{
	ELA_ASSERT_INT_EQ(8, (int)ela_uboot_image_align_up_4(8));
}

static void test_align_three(void)
{
	ELA_ASSERT_INT_EQ(4, (int)ela_uboot_image_align_up_4(3));
}

static void test_align_twelve(void)
{
	ELA_ASSERT_INT_EQ(12, (int)ela_uboot_image_align_up_4(12));
}

static void test_align_thirteen(void)
{
	ELA_ASSERT_INT_EQ(16, (int)ela_uboot_image_align_up_4(13));
}

/* =========================================================================
 * ela_uboot_image_str_contains_token_ci
 * ====================================================================== */

static void test_token_ci_null_haystack(void)
{
	ELA_ASSERT_FALSE(ela_uboot_image_str_contains_token_ci(NULL, "u-boot"));
}

static void test_token_ci_null_needle(void)
{
	ELA_ASSERT_FALSE(ela_uboot_image_str_contains_token_ci("U-Boot", NULL));
}

static void test_token_ci_empty_needle_returns_true(void)
{
	/* empty needle: strlen==0, returns true immediately */
	ELA_ASSERT_TRUE(ela_uboot_image_str_contains_token_ci("anything", ""));
}

static void test_token_ci_exact_match(void)
{
	ELA_ASSERT_TRUE(ela_uboot_image_str_contains_token_ci("u-boot", "u-boot"));
}

static void test_token_ci_case_insensitive_match(void)
{
	ELA_ASSERT_TRUE(ela_uboot_image_str_contains_token_ci("Booting U-Boot image", "u-boot"));
}

static void test_token_ci_needle_larger_case(void)
{
	ELA_ASSERT_TRUE(ela_uboot_image_str_contains_token_ci("u-boot", "U-BOOT"));
}

static void test_token_ci_haystack_contains_needle_at_start(void)
{
	ELA_ASSERT_TRUE(ela_uboot_image_str_contains_token_ci("firmware payload", "firmware"));
}

static void test_token_ci_haystack_contains_needle_at_end(void)
{
	ELA_ASSERT_TRUE(ela_uboot_image_str_contains_token_ci("load firmware", "firmware"));
}

static void test_token_ci_no_match(void)
{
	ELA_ASSERT_FALSE(ela_uboot_image_str_contains_token_ci("firmware", "kernel"));
}

static void test_token_ci_empty_haystack(void)
{
	ELA_ASSERT_FALSE(ela_uboot_image_str_contains_token_ci("", "u-boot"));
}

static void test_token_ci_needle_longer_than_haystack(void)
{
	ELA_ASSERT_FALSE(ela_uboot_image_str_contains_token_ci("hi", "u-boot-spl"));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_image_format_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "detect/null_returns_txt",          test_detect_null_returns_txt },
		{ "detect/empty_returns_txt",         test_detect_empty_returns_txt },
		{ "detect/txt_explicit",              test_detect_txt_explicit },
		{ "detect/csv",                       test_detect_csv },
		{ "detect/json",                      test_detect_json },
		{ "detect/unknown_fallback",          test_detect_unknown_falls_back_to_txt },
		{ "content_type/txt",                 test_content_type_txt },
		{ "content_type/csv",                 test_content_type_csv },
		{ "content_type/json",                test_content_type_json },
		{ "content_type/unknown_plain",       test_content_type_unknown_returns_plain },
		{ "align/zero",                       test_align_zero },
		{ "align/one",                        test_align_one },
		{ "align/already_aligned",            test_align_already_aligned },
		{ "align/five",                       test_align_five },
		{ "align/seven",                      test_align_seven },
		{ "align/eight",                      test_align_eight },
		{ "align/three",                      test_align_three },
		{ "align/twelve",                     test_align_twelve },
		{ "align/thirteen",                   test_align_thirteen },
		{ "token_ci/null_haystack",           test_token_ci_null_haystack },
		{ "token_ci/null_needle",             test_token_ci_null_needle },
		{ "token_ci/empty_needle_true",       test_token_ci_empty_needle_returns_true },
		{ "token_ci/exact_match",             test_token_ci_exact_match },
		{ "token_ci/case_insensitive",        test_token_ci_case_insensitive_match },
		{ "token_ci/needle_upper_case",       test_token_ci_needle_larger_case },
		{ "token_ci/needle_at_start",         test_token_ci_haystack_contains_needle_at_start },
		{ "token_ci/needle_at_end",           test_token_ci_haystack_contains_needle_at_end },
		{ "token_ci/no_match",                test_token_ci_no_match },
		{ "token_ci/empty_haystack",          test_token_ci_empty_haystack },
		{ "token_ci/needle_longer",           test_token_ci_needle_longer_than_haystack },
	};
	return ela_run_test_suite("uboot_image_format_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
