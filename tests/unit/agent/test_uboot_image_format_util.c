// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/image/uboot_image_format_util.h"

static void test_uboot_image_format_helpers(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_TXT, ela_uboot_image_detect_output_format(NULL));
	ELA_ASSERT_INT_EQ(FW_OUTPUT_CSV, ela_uboot_image_detect_output_format("csv"));
	ELA_ASSERT_INT_EQ(FW_OUTPUT_JSON, ela_uboot_image_detect_output_format("json"));
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8", ela_uboot_image_http_content_type(FW_OUTPUT_TXT));
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8", ela_uboot_image_http_content_type(FW_OUTPUT_CSV));
	ELA_ASSERT_STR_EQ("application/x-ndjson; charset=utf-8", ela_uboot_image_http_content_type(FW_OUTPUT_JSON));
}

static void test_uboot_image_align_and_token_helpers(void)
{
	ELA_ASSERT_INT_EQ(0, (int)ela_uboot_image_align_up_4(0));
	ELA_ASSERT_INT_EQ(4, (int)ela_uboot_image_align_up_4(1));
	ELA_ASSERT_INT_EQ(8, (int)ela_uboot_image_align_up_4(5));
	ELA_ASSERT_TRUE(ela_uboot_image_str_contains_token_ci("Booting U-Boot image", "u-boot"));
	ELA_ASSERT_FALSE(ela_uboot_image_str_contains_token_ci("firmware", "kernel"));
}

int run_uboot_image_format_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "uboot_image_format_helpers", test_uboot_image_format_helpers },
		{ "uboot_image_align_and_token_helpers", test_uboot_image_align_and_token_helpers },
	};

	return ela_run_test_suite("uboot_image_format_util", cases, sizeof(cases) / sizeof(cases[0]));
}
