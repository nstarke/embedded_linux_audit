// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/image/uboot_image_record_util.h"

#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * ela_uboot_image_format_record
 * ====================================================================== */

static void test_record_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_format_record(
		FW_OUTPUT_JSON, NULL, "rec", "/dev/mtd0", 0x100,
		"type", "val", NULL));
}

static void test_record_txt_returns_zero_no_output(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_record(
		FW_OUTPUT_TXT, &hdr, "rec", "/dev/mtd0", 0x100,
		"type", "val", &out));
	ELA_ASSERT_TRUE(out == NULL);
}

static void test_record_csv_first_includes_header(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_record(
		FW_OUTPUT_CSV, &hdr, "myrecord", "/dev/mtd0", 0x200,
		"mytype", "myval", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "record,device,offset,type,value\n") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "myrecord") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "/dev/mtd0") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "0x200") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "mytype") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "myval") != NULL);
	ELA_ASSERT_TRUE(hdr);
	free(out);
}

static void test_record_csv_second_no_header(void)
{
	char *out1 = NULL, *out2 = NULL;
	bool hdr = false;

	ela_uboot_image_format_record(FW_OUTPUT_CSV, &hdr, "r1", "/dev/mtd0",
				      0, "t1", "v1", &out1);
	ela_uboot_image_format_record(FW_OUTPUT_CSV, &hdr, "r2", "/dev/mtd1",
				      0, "t2", "v2", &out2);
	ELA_ASSERT_TRUE(strstr(out2, "record,device") == NULL);
	ELA_ASSERT_TRUE(strstr(out2, "r2") != NULL);
	free(out1);
	free(out2);
}

static void test_record_json(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_record(
		FW_OUTPUT_JSON, &hdr, "image_cmd", "/dev/mtd0", 0x400,
		"load", "0x80000000", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"record\":\"image_cmd\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"device\":\"/dev/mtd0\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"offset\":1024") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"type\":\"load\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"value\":\"0x80000000\"") != NULL);
	free(out);
}

static void test_record_json_null_device(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_record(
		FW_OUTPUT_JSON, &hdr, "rec", NULL, 0,
		"type", "val", &out));
	ELA_ASSERT_TRUE(out != NULL);
	/* no "device" key when dev is NULL */
	ELA_ASSERT_TRUE(strstr(out, "\"device\"") == NULL);
	free(out);
}

static void test_record_json_null_value(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_record(
		FW_OUTPUT_JSON, &hdr, "rec", "/dev/mtd0", 0,
		"type", NULL, &out));
	ELA_ASSERT_TRUE(out != NULL);
	/* no "value" key when value is NULL */
	ELA_ASSERT_TRUE(strstr(out, "\"value\"") == NULL);
	free(out);
}

/* =========================================================================
 * ela_uboot_image_format_verbose
 * ====================================================================== */

static void test_verbose_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_format_verbose(
		FW_OUTPUT_TXT, true, NULL, "/dev/mtd0", 0, "msg", NULL));
}

static void test_verbose_not_verbose(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_verbose(
		FW_OUTPUT_TXT, false, &hdr, "/dev/mtd0", 0, "msg", &out));
	ELA_ASSERT_TRUE(out == NULL);
}

static void test_verbose_null_msg(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_verbose(
		FW_OUTPUT_TXT, true, &hdr, "/dev/mtd0", 0, NULL, &out));
	ELA_ASSERT_TRUE(out == NULL);
}

static void test_verbose_txt(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_verbose(
		FW_OUTPUT_TXT, true, &hdr, "/dev/mtd0", 0,
		"Scanning device", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_STR_EQ("Scanning device\n", out);
	free(out);
}

static void test_verbose_csv(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_verbose(
		FW_OUTPUT_CSV, true, &hdr, "/dev/mtd0", 0x100,
		"some log message", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "verbose") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "some log message") != NULL);
	free(out);
}

static void test_verbose_json(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_verbose(
		FW_OUTPUT_JSON, true, &hdr, "/dev/mtd0", 0x200,
		"scan log", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"record\":\"verbose\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"type\":\"log\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"value\":\"scan log\"") != NULL);
	free(out);
}

/* =========================================================================
 * ela_uboot_image_format_signature
 * ====================================================================== */

static void test_signature_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_uboot_image_format_signature(
		FW_OUTPUT_TXT, NULL, "/dev/mtd0", 0x120, "FIT", NULL));
}

static void test_signature_txt(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_signature(
		FW_OUTPUT_TXT, &hdr, "/dev/mtd0", 0x120, "FIT", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "candidate image signature: /dev/mtd0 offset=0x120 type=FIT") != NULL);
	free(out);
}

static void test_signature_csv(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_signature(
		FW_OUTPUT_CSV, &hdr, "/dev/mtd0", 0x120, "FIT", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "record,device,offset,type,value\n") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "image_signature") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "/dev/mtd0") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "0x120") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "FIT") != NULL);
	free(out);
}

static void test_signature_json(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_signature(
		FW_OUTPUT_JSON, &hdr, "/dev/mtd0", 0x120, "FIT", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"record\":\"image_signature\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"device\":\"/dev/mtd0\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "\"type\":\"FIT\"") != NULL);
	free(out);
}

static void test_signature_uimage_txt(void)
{
	char *out = NULL;
	bool hdr = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_image_format_signature(
		FW_OUTPUT_TXT, &hdr, "/dev/mtd1", 0x0, "uImage", &out));
	ELA_ASSERT_TRUE(out != NULL);
	ELA_ASSERT_TRUE(strstr(out, "uImage") != NULL);
	ELA_ASSERT_TRUE(strstr(out, "/dev/mtd1") != NULL);
	free(out);
}

/* =========================================================================
 * ela_uboot_image_matches_text_pattern
 * ====================================================================== */

static void test_text_pattern_null_buf(void)
{
	ELA_ASSERT_FALSE(ela_uboot_image_matches_text_pattern(
		NULL, 10, 0, "U-Boot"));
}

static void test_text_pattern_null_pattern(void)
{
	static const uint8_t buf[] = "U-Boot";
	ELA_ASSERT_FALSE(ela_uboot_image_matches_text_pattern(
		buf, sizeof(buf) - 1, 0, NULL));
}

static void test_text_pattern_empty_pattern(void)
{
	static const uint8_t buf[] = "U-Boot";
	ELA_ASSERT_FALSE(ela_uboot_image_matches_text_pattern(
		buf, sizeof(buf) - 1, 0, ""));
}

static void test_text_pattern_match_at_start(void)
{
	static const uint8_t buf[] = "U-Boot image";
	ELA_ASSERT_TRUE(ela_uboot_image_matches_text_pattern(
		buf, sizeof(buf) - 1, 0, "U-Boot"));
}

static void test_text_pattern_match_at_offset(void)
{
	static const uint8_t buf[] = "123U-Boot456";
	ELA_ASSERT_TRUE(ela_uboot_image_matches_text_pattern(
		buf, sizeof(buf) - 1, 3, "U-Boot"));
}

static void test_text_pattern_wrong_offset(void)
{
	static const uint8_t buf[] = "123U-Boot456";
	ELA_ASSERT_FALSE(ela_uboot_image_matches_text_pattern(
		buf, sizeof(buf) - 1, 4, "U-Boot"));
}

static void test_text_pattern_pos_plus_len_exceeds_buf(void)
{
	static const uint8_t buf[] = "U-Boot";
	/* pattern is "U-Boot" (6 chars); pos=2 → would need pos+6=8 > 6 */
	ELA_ASSERT_FALSE(ela_uboot_image_matches_text_pattern(
		buf, sizeof(buf) - 1, 2, "U-Boot"));
}

static void test_text_pattern_exact_fit_at_end(void)
{
	static const uint8_t buf[] = "xyzfoo";
	ELA_ASSERT_TRUE(ela_uboot_image_matches_text_pattern(
		buf, sizeof(buf) - 1, 3, "foo"));
}

/* =========================================================================
 * ela_uboot_image_classify_signature_kind
 * ====================================================================== */

static void test_classify_uimage(void)
{
	ELA_ASSERT_STR_EQ("uImage",
			  ela_uboot_image_classify_signature_kind(true, false, false));
}

static void test_classify_fit(void)
{
	ELA_ASSERT_STR_EQ("FIT",
			  ela_uboot_image_classify_signature_kind(false, true, false));
}

static void test_classify_text(void)
{
	ELA_ASSERT_STR_EQ("U-Boot-text",
			  ela_uboot_image_classify_signature_kind(false, false, true));
}

static void test_classify_none(void)
{
	ELA_ASSERT_TRUE(ela_uboot_image_classify_signature_kind(false, false, false) == NULL);
}

static void test_classify_uimage_takes_priority_over_fit(void)
{
	/* uimage_valid wins over fit_valid */
	ELA_ASSERT_STR_EQ("uImage",
			  ela_uboot_image_classify_signature_kind(true, true, false));
}

static void test_classify_fit_takes_priority_over_text(void)
{
	ELA_ASSERT_STR_EQ("FIT",
			  ela_uboot_image_classify_signature_kind(false, true, true));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_image_record_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* format_record */
		{ "record/null_out",                 test_record_null_out },
		{ "record/txt_no_output",            test_record_txt_returns_zero_no_output },
		{ "record/csv_with_header",          test_record_csv_first_includes_header },
		{ "record/csv_second_no_header",     test_record_csv_second_no_header },
		{ "record/json",                     test_record_json },
		{ "record/json_null_device",         test_record_json_null_device },
		{ "record/json_null_value",          test_record_json_null_value },
		/* format_verbose */
		{ "verbose/null_out",                test_verbose_null_out },
		{ "verbose/not_verbose",             test_verbose_not_verbose },
		{ "verbose/null_msg",                test_verbose_null_msg },
		{ "verbose/txt",                     test_verbose_txt },
		{ "verbose/csv",                     test_verbose_csv },
		{ "verbose/json",                    test_verbose_json },
		/* format_signature */
		{ "signature/null_out",              test_signature_null_out },
		{ "signature/txt",                   test_signature_txt },
		{ "signature/csv",                   test_signature_csv },
		{ "signature/json",                  test_signature_json },
		{ "signature/uimage_txt",            test_signature_uimage_txt },
		/* matches_text_pattern */
		{ "text_pattern/null_buf",           test_text_pattern_null_buf },
		{ "text_pattern/null_pattern",       test_text_pattern_null_pattern },
		{ "text_pattern/empty_pattern",      test_text_pattern_empty_pattern },
		{ "text_pattern/match_at_start",     test_text_pattern_match_at_start },
		{ "text_pattern/match_at_offset",    test_text_pattern_match_at_offset },
		{ "text_pattern/wrong_offset",       test_text_pattern_wrong_offset },
		{ "text_pattern/pos_overrun",        test_text_pattern_pos_plus_len_exceeds_buf },
		{ "text_pattern/exact_end",          test_text_pattern_exact_fit_at_end },
		/* classify_signature_kind */
		{ "classify/uimage",                 test_classify_uimage },
		{ "classify/fit",                    test_classify_fit },
		{ "classify/text",                   test_classify_text },
		{ "classify/none",                   test_classify_none },
		{ "classify/uimage_priority",        test_classify_uimage_takes_priority_over_fit },
		{ "classify/fit_priority",           test_classify_fit_takes_priority_over_text },
	};
	return ela_run_test_suite("uboot_image_record_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
