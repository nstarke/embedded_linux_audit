// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/uboot_security_audit_util.h"

#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * ela_uboot_buffer_has_newline
 * ====================================================================== */

static void test_has_newline_null_buf(void)
{
	ELA_ASSERT_FALSE(ela_uboot_buffer_has_newline(NULL, 3));
}

static void test_has_newline_zero_len(void)
{
	ELA_ASSERT_FALSE(ela_uboot_buffer_has_newline("abc", 0));
}

static void test_has_newline_no_newline(void)
{
	ELA_ASSERT_FALSE(ela_uboot_buffer_has_newline("abcdef", 6));
}

static void test_has_newline_newline_only(void)
{
	ELA_ASSERT_TRUE(ela_uboot_buffer_has_newline("\n", 1));
}

static void test_has_newline_at_start(void)
{
	ELA_ASSERT_TRUE(ela_uboot_buffer_has_newline("\nabc", 4));
}

static void test_has_newline_at_middle(void)
{
	ELA_ASSERT_TRUE(ela_uboot_buffer_has_newline("a\nb", 3));
}

static void test_has_newline_at_end(void)
{
	ELA_ASSERT_TRUE(ela_uboot_buffer_has_newline("abc\n", 4));
}

static void test_has_newline_multiple(void)
{
	ELA_ASSERT_TRUE(ela_uboot_buffer_has_newline("a\nb\nc", 5));
}

static void test_has_newline_len_shorter_than_buf(void)
{
	/* newline is at position 3 but len=3, so it's excluded */
	ELA_ASSERT_FALSE(ela_uboot_buffer_has_newline("abc\n", 3));
}

/* =========================================================================
 * ela_uboot_audit_rule_may_need_signature_artifacts
 * ====================================================================== */

static void test_rule_may_need_null(void)
{
	ELA_ASSERT_TRUE(ela_uboot_audit_rule_may_need_signature_artifacts(NULL));
}

static void test_rule_may_need_empty(void)
{
	ELA_ASSERT_TRUE(ela_uboot_audit_rule_may_need_signature_artifacts(""));
}

static void test_rule_may_need_secureboot(void)
{
	ELA_ASSERT_TRUE(ela_uboot_audit_rule_may_need_signature_artifacts(
		"uboot_validate_secureboot"));
}

static void test_rule_may_need_other_rule(void)
{
	ELA_ASSERT_FALSE(ela_uboot_audit_rule_may_need_signature_artifacts("other_rule"));
}

static void test_rule_may_need_crc32_rule(void)
{
	ELA_ASSERT_FALSE(ela_uboot_audit_rule_may_need_signature_artifacts(
		"uboot_validate_crc32"));
}

/* =========================================================================
 * ela_uboot_audit_detect_output_format
 * ====================================================================== */

static void test_detect_fmt_null(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_TXT, ela_uboot_audit_detect_output_format(NULL));
}

static void test_detect_fmt_empty(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_TXT, ela_uboot_audit_detect_output_format(""));
}

static void test_detect_fmt_txt(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_TXT, ela_uboot_audit_detect_output_format("txt"));
}

static void test_detect_fmt_csv(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_CSV, ela_uboot_audit_detect_output_format("csv"));
}

static void test_detect_fmt_json(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_JSON, ela_uboot_audit_detect_output_format("json"));
}

static void test_detect_fmt_unknown(void)
{
	ELA_ASSERT_INT_EQ(FW_OUTPUT_TXT, ela_uboot_audit_detect_output_format("xml"));
}

static void test_detect_fmt_case_sensitive(void)
{
	/* format strings are case-sensitive; "CSV" should fall back to TXT */
	ELA_ASSERT_INT_EQ(FW_OUTPUT_TXT, ela_uboot_audit_detect_output_format("CSV"));
}

/* =========================================================================
 * ela_uboot_read_be32
 * ====================================================================== */

static void test_read_be32_zero(void)
{
	uint8_t b[] = { 0x00, 0x00, 0x00, 0x00 };
	ELA_ASSERT_INT_EQ(0, (int)ela_uboot_read_be32(b));
}

static void test_read_be32_max(void)
{
	uint8_t b[] = { 0xff, 0xff, 0xff, 0xff };
	ELA_ASSERT_INT_EQ((int)0xffffffffU, (int)ela_uboot_read_be32(b));
}

static void test_read_be32_known_value(void)
{
	uint8_t b[] = { 0x12, 0x34, 0x56, 0x78 };
	ELA_ASSERT_INT_EQ(0x12345678, (int)ela_uboot_read_be32(b));
}

static void test_read_be32_high_bit(void)
{
	uint8_t b[] = { 0xD0, 0x0D, 0xFE, 0xED };
	ELA_ASSERT_INT_EQ((int)0xD00DFEEDu, (int)ela_uboot_read_be32(b));
}

/* =========================================================================
 * ela_uboot_fit_header_looks_valid
 * ====================================================================== */

static void put_be32_audit(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)((v >> 24) & 0xff);
	p[1] = (uint8_t)((v >> 16) & 0xff);
	p[2] = (uint8_t)((v >>  8) & 0xff);
	p[3] = (uint8_t)(v & 0xff);
}

/* Build a valid 40-byte FIT header buffer */
static void make_valid_audit_fit_hdr(uint8_t *h)
{
	memset(h, 0, 40);
	put_be32_audit(h +  4, 0x120);  /* totalsize */
	put_be32_audit(h +  8, 0x40);   /* off_dt_struct */
	put_be32_audit(h + 12, 0xa0);   /* off_dt_strings */
	put_be32_audit(h + 16, 0x28);   /* off_mem_rsvmap (>= 40) */
	put_be32_audit(h + 20, 0x11);   /* version = 17 */
	put_be32_audit(h + 24, 0x10);   /* last_comp_version = 16 */
	put_be32_audit(h + 32, 0x20);   /* size_dt_strings */
	put_be32_audit(h + 36, 0x40);   /* size_dt_struct */
}

static void test_fit_hdr_valid(void)
{
	uint8_t h[40];
	make_valid_audit_fit_hdr(h);
	ELA_ASSERT_TRUE(ela_uboot_fit_header_looks_valid(h, 0, 0x2000));
}

static void test_fit_hdr_totalsize_too_small(void)
{
	uint8_t h[40];
	make_valid_audit_fit_hdr(h);
	put_be32_audit(h + 4, 0x0f); /* below FIT_MIN_TOTAL_SIZE (0x100) */
	ELA_ASSERT_FALSE(ela_uboot_fit_header_looks_valid(h, 0, 0x2000));
}

static void test_fit_hdr_totalsize_too_large(void)
{
	uint8_t h[40];
	make_valid_audit_fit_hdr(h);
	put_be32_audit(h + 4, 0x04000001); /* above 64 MiB */
	ELA_ASSERT_FALSE(ela_uboot_fit_header_looks_valid(h, 0, 0x10000000));
}

static void test_fit_hdr_exceeds_dev_size(void)
{
	uint8_t h[40];
	make_valid_audit_fit_hdr(h); /* totalsize=0x120 */
	ELA_ASSERT_FALSE(ela_uboot_fit_header_looks_valid(h, 0x100, 0x200));
}

static void test_fit_hdr_mem_rsvmap_too_small(void)
{
	uint8_t h[40];
	make_valid_audit_fit_hdr(h);
	put_be32_audit(h + 16, 10); /* < 40 */
	ELA_ASSERT_FALSE(ela_uboot_fit_header_looks_valid(h, 0, 0x2000));
}

static void test_fit_hdr_size_dt_strings_zero(void)
{
	uint8_t h[40];
	make_valid_audit_fit_hdr(h);
	put_be32_audit(h + 32, 0);
	ELA_ASSERT_FALSE(ela_uboot_fit_header_looks_valid(h, 0, 0x2000));
}

static void test_fit_hdr_size_dt_struct_zero(void)
{
	uint8_t h[40];
	make_valid_audit_fit_hdr(h);
	put_be32_audit(h + 36, 0);
	ELA_ASSERT_FALSE(ela_uboot_fit_header_looks_valid(h, 0, 0x2000));
}

static void test_fit_hdr_version_out_of_range(void)
{
	uint8_t h[40];
	make_valid_audit_fit_hdr(h);
	put_be32_audit(h + 20, 15); /* < 16 */
	ELA_ASSERT_FALSE(ela_uboot_fit_header_looks_valid(h, 0, 0x2000));
}

static void test_fit_hdr_last_comp_gt_version(void)
{
	uint8_t h[40];
	make_valid_audit_fit_hdr(h);
	put_be32_audit(h + 20, 16);
	put_be32_audit(h + 24, 17); /* last_comp > version */
	ELA_ASSERT_FALSE(ela_uboot_fit_header_looks_valid(h, 0, 0x2000));
}

/* =========================================================================
 * ela_uboot_extract_public_key_pem
 * ====================================================================== */

static void test_pem_null_text(void)
{
	char *pem = NULL;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_extract_public_key_pem(NULL, 10, &pem));
}

static void test_pem_null_out(void)
{
	const char *s = "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----\n";
	ELA_ASSERT_INT_EQ(-1, ela_uboot_extract_public_key_pem(s, strlen(s), NULL));
}

static void test_pem_no_begin_marker(void)
{
	const char *s = "noise-----END PUBLIC KEY-----";
	char *pem = NULL;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_extract_public_key_pem(s, strlen(s), &pem));
}

static void test_pem_no_end_marker(void)
{
	const char *s = "-----BEGIN PUBLIC KEY-----\nABC";
	char *pem = NULL;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_extract_public_key_pem(s, strlen(s), &pem));
}

static void test_pem_basic_extraction(void)
{
	const char *blob = "noise-----BEGIN PUBLIC KEY-----\nABCDEF\n-----END PUBLIC KEY-----tail";
	char *pem = NULL;
	ELA_ASSERT_INT_EQ(0, ela_uboot_extract_public_key_pem(blob, strlen(blob), &pem));
	ELA_ASSERT_STR_EQ("-----BEGIN PUBLIC KEY-----\nABCDEF\n-----END PUBLIC KEY-----\n", pem);
	free(pem);
}

static void test_pem_already_ends_with_newline(void)
{
	/* pem body already ends with \n before END marker */
	const char *blob = "-----BEGIN PUBLIC KEY-----\nDATA\n-----END PUBLIC KEY-----\n";
	char *pem = NULL;
	ELA_ASSERT_INT_EQ(0, ela_uboot_extract_public_key_pem(blob, strlen(blob), &pem));
	/* should end with exactly one \n */
	ELA_ASSERT_TRUE(pem != NULL);
	size_t len = strlen(pem);
	ELA_ASSERT_TRUE(len > 0 && pem[len - 1] == '\n');
	free(pem);
}

static void test_pem_no_newline_before_end(void)
{
	/* no newline between body and END marker — implementation appends one */
	const char *blob = "-----BEGIN PUBLIC KEY-----\nDATA-----END PUBLIC KEY-----";
	char *pem = NULL;
	ELA_ASSERT_INT_EQ(0, ela_uboot_extract_public_key_pem(blob, strlen(blob), &pem));
	ELA_ASSERT_TRUE(pem != NULL);
	size_t len = strlen(pem);
	ELA_ASSERT_TRUE(len > 0 && pem[len - 1] == '\n');
	free(pem);
}

static void test_pem_begin_only_exact_len(void)
{
	/* text is exactly the begin marker with no end marker */
	const char *s = "-----BEGIN PUBLIC KEY-----";
	char *pem = NULL;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_extract_public_key_pem(s, strlen(s), &pem));
}

static void test_pem_content_preserved(void)
{
	const char *blob =
		"-----BEGIN PUBLIC KEY-----\n"
		"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL\n"
		"-----END PUBLIC KEY-----\n";
	char *pem = NULL;
	ELA_ASSERT_INT_EQ(0, ela_uboot_extract_public_key_pem(blob, strlen(blob), &pem));
	ELA_ASSERT_TRUE(strstr(pem, "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL") != NULL);
	free(pem);
}

/* =========================================================================
 * ela_uboot_audit_http_buf_append
 * ====================================================================== */

static void test_http_buf_null_buf_ptr(void)
{
	size_t len = 0, cap = 0;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_audit_http_buf_append(
		NULL, &len, &cap, "hello", 5));
}

static void test_http_buf_null_len(void)
{
	char *buf = NULL;
	size_t cap = 0;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_audit_http_buf_append(
		&buf, NULL, &cap, "hello", 5));
}

static void test_http_buf_null_cap(void)
{
	char *buf = NULL;
	size_t len = 0;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_audit_http_buf_append(
		&buf, &len, NULL, "hello", 5));
}

static void test_http_buf_null_data(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_audit_http_buf_append(
		&buf, &len, &cap, NULL, 5));
}

static void test_http_buf_zero_data_len(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_audit_http_buf_append(
		&buf, &len, &cap, "hello", 0));
}

static void test_http_buf_first_append(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	ELA_ASSERT_INT_EQ(0, ela_uboot_audit_http_buf_append(
		&buf, &len, &cap, "hello", 5));
	ELA_ASSERT_INT_EQ(5, (int)len);
	ELA_ASSERT_TRUE(cap >= 6);
	ELA_ASSERT_STR_EQ("hello", buf);
	free(buf);
}

static void test_http_buf_second_append(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	ELA_ASSERT_INT_EQ(0, ela_uboot_audit_http_buf_append(
		&buf, &len, &cap, "hello", 5));
	ELA_ASSERT_INT_EQ(0, ela_uboot_audit_http_buf_append(
		&buf, &len, &cap, " world", 6));
	ELA_ASSERT_INT_EQ(11, (int)len);
	ELA_ASSERT_STR_EQ("hello world", buf);
	free(buf);
}

static void test_http_buf_nul_terminated(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	ELA_ASSERT_INT_EQ(0, ela_uboot_audit_http_buf_append(
		&buf, &len, &cap, "abc", 3));
	ELA_ASSERT_TRUE(buf[len] == '\0');
	free(buf);
}

static void test_http_buf_grows_past_initial_cap(void)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	/* Append enough data to force at least one realloc (initial cap=1024) */
	char big[1100];
	memset(big, 'x', sizeof(big));
	ELA_ASSERT_INT_EQ(0, ela_uboot_audit_http_buf_append(
		&buf, &len, &cap, big, sizeof(big)));
	ELA_ASSERT_INT_EQ((int)sizeof(big), (int)len);
	ELA_ASSERT_TRUE(cap > sizeof(big));
	ELA_ASSERT_TRUE(buf[len] == '\0');
	free(buf);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_security_audit_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* buffer_has_newline */
		{ "has_newline/null_buf",            test_has_newline_null_buf },
		{ "has_newline/zero_len",            test_has_newline_zero_len },
		{ "has_newline/no_newline",          test_has_newline_no_newline },
		{ "has_newline/newline_only",        test_has_newline_newline_only },
		{ "has_newline/at_start",            test_has_newline_at_start },
		{ "has_newline/at_middle",           test_has_newline_at_middle },
		{ "has_newline/at_end",              test_has_newline_at_end },
		{ "has_newline/multiple",            test_has_newline_multiple },
		{ "has_newline/len_excludes",        test_has_newline_len_shorter_than_buf },
		/* rule_may_need_signature_artifacts */
		{ "rule_may_need/null",              test_rule_may_need_null },
		{ "rule_may_need/empty",             test_rule_may_need_empty },
		{ "rule_may_need/secureboot",        test_rule_may_need_secureboot },
		{ "rule_may_need/other",             test_rule_may_need_other_rule },
		{ "rule_may_need/crc32",             test_rule_may_need_crc32_rule },
		/* detect_output_format */
		{ "detect_fmt/null",                 test_detect_fmt_null },
		{ "detect_fmt/empty",                test_detect_fmt_empty },
		{ "detect_fmt/txt",                  test_detect_fmt_txt },
		{ "detect_fmt/csv",                  test_detect_fmt_csv },
		{ "detect_fmt/json",                 test_detect_fmt_json },
		{ "detect_fmt/unknown",              test_detect_fmt_unknown },
		{ "detect_fmt/case_sensitive",       test_detect_fmt_case_sensitive },
		/* read_be32 */
		{ "read_be32/zero",                  test_read_be32_zero },
		{ "read_be32/max",                   test_read_be32_max },
		{ "read_be32/known",                 test_read_be32_known_value },
		{ "read_be32/high_bit",              test_read_be32_high_bit },
		/* fit_header_looks_valid */
		{ "fit_hdr/valid",                   test_fit_hdr_valid },
		{ "fit_hdr/totalsize_too_small",     test_fit_hdr_totalsize_too_small },
		{ "fit_hdr/totalsize_too_large",     test_fit_hdr_totalsize_too_large },
		{ "fit_hdr/exceeds_dev_size",        test_fit_hdr_exceeds_dev_size },
		{ "fit_hdr/mem_rsvmap_too_small",    test_fit_hdr_mem_rsvmap_too_small },
		{ "fit_hdr/size_dt_strings_zero",    test_fit_hdr_size_dt_strings_zero },
		{ "fit_hdr/size_dt_struct_zero",     test_fit_hdr_size_dt_struct_zero },
		{ "fit_hdr/version_out_of_range",    test_fit_hdr_version_out_of_range },
		{ "fit_hdr/last_comp_gt_version",    test_fit_hdr_last_comp_gt_version },
		/* extract_public_key_pem */
		{ "pem/null_text",                   test_pem_null_text },
		{ "pem/null_out",                    test_pem_null_out },
		{ "pem/no_begin_marker",             test_pem_no_begin_marker },
		{ "pem/no_end_marker",               test_pem_no_end_marker },
		{ "pem/basic_extraction",            test_pem_basic_extraction },
		{ "pem/already_ends_with_newline",   test_pem_already_ends_with_newline },
		{ "pem/no_newline_before_end",       test_pem_no_newline_before_end },
		{ "pem/begin_only",                  test_pem_begin_only_exact_len },
		{ "pem/content_preserved",           test_pem_content_preserved },
		/* http_buf_append */
		{ "http_buf/null_buf_ptr",           test_http_buf_null_buf_ptr },
		{ "http_buf/null_len",               test_http_buf_null_len },
		{ "http_buf/null_cap",               test_http_buf_null_cap },
		{ "http_buf/null_data",              test_http_buf_null_data },
		{ "http_buf/zero_data_len",          test_http_buf_zero_data_len },
		{ "http_buf/first_append",           test_http_buf_first_append },
		{ "http_buf/second_append",          test_http_buf_second_append },
		{ "http_buf/nul_terminated",         test_http_buf_nul_terminated },
		{ "http_buf/grows_past_cap",         test_http_buf_grows_past_initial_cap },
	};
	return ela_run_test_suite("uboot_security_audit_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
