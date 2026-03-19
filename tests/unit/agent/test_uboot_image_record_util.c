// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/image/uboot_image_record_util.h"

#include <stdlib.h>
#include <string.h>

static void test_uboot_image_record_formatter_helpers(void)
{
	char *out = NULL;
	bool csv_header_emitted = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_signature(FW_OUTPUT_TXT,
							      &csv_header_emitted,
							      "/dev/mtd0",
							      0x120,
							      "FIT",
							      &out));
	ELA_ASSERT_TRUE(strstr(out, "candidate image signature: /dev/mtd0 offset=0x120 type=FIT") != NULL);
	free(out);
	out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_signature(FW_OUTPUT_CSV,
							      &csv_header_emitted,
							      "/dev/mtd0",
							      0x120,
							      "FIT",
							      &out));
	ELA_ASSERT_TRUE(strstr(out, "record,device,offset,type,value\n") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "image_signature") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "/dev/mtd0") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "0x120") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "FIT") != NULL);
	free(out);
	out = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_signature(FW_OUTPUT_JSON,
							      &csv_header_emitted,
							      "/dev/mtd0",
							      0x120,
							      "FIT",
							      &out));
	ELA_ASSERT_TRUE(strstr(out, "\"record\":\"image_signature\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"device\":\"/dev/mtd0\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"type\":\"FIT\"") != NULL);
	free(out);
}

static void test_uboot_image_verbose_and_scan_heuristics(void)
{
	char *out = NULL;
	bool csv_header_emitted = false;
	static const uint8_t blob[] = "123U-Boot456";

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_verbose(FW_OUTPUT_TXT,
							    true,
							    &csv_header_emitted,
							    "/dev/mtd1",
							    0,
							    "Scanning",
							    &out));
	ELA_ASSERT_STR_EQ("Scanning\n", out);
	free(out);
	out = NULL;

	ELA_ASSERT_TRUE(ela_uboot_image_matches_text_pattern(blob, sizeof(blob) - 1, 3, "U-Boot"));
	ELA_ASSERT_FALSE(ela_uboot_image_matches_text_pattern(blob, sizeof(blob) - 1, 4, "U-Boot"));
	ELA_ASSERT_STR_EQ("uImage", ela_uboot_image_classify_signature_kind(true, false, false));
	ELA_ASSERT_STR_EQ("FIT", ela_uboot_image_classify_signature_kind(false, true, false));
	ELA_ASSERT_STR_EQ("U-Boot-text", ela_uboot_image_classify_signature_kind(false, false, true));
	ELA_ASSERT_TRUE(ela_uboot_image_classify_signature_kind(false, false, false) == NULL);
}

int run_uboot_image_record_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "uboot_image_record_formatter_helpers", test_uboot_image_record_formatter_helpers },
		{ "uboot_image_verbose_and_scan_heuristics", test_uboot_image_verbose_and_scan_heuristics },
	};

	return ela_run_test_suite("uboot_image_record_util", cases, sizeof(cases) / sizeof(cases[0]));
}
