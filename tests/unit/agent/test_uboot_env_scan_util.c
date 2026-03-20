// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/env/uboot_env_scan_util.h"

#include <stdlib.h>

/* =========================================================================
 * ela_uboot_env_add_or_merge_candidate
 * ====================================================================== */

static void test_merge_null_cands(void)
{
	size_t count = 0;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_add_or_merge_candidate(
		NULL, &count, 0x1000, true, false));
}

static void test_merge_null_count(void)
{
	struct ela_uboot_env_candidate *cands = NULL;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_add_or_merge_candidate(
		&cands, NULL, 0x1000, true, false));
}

static void test_merge_fresh_add(void)
{
	struct ela_uboot_env_candidate *cands = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_add_or_merge_candidate(
		&cands, &count, 0x1000, true, false));
	ELA_ASSERT_INT_EQ(1, (int)count);
	ELA_ASSERT_TRUE(cands[0].cfg_off == 0x1000);
	ELA_ASSERT_TRUE(cands[0].crc_standard);
	ELA_ASSERT_FALSE(cands[0].crc_redundant);
	free(cands);
}

static void test_merge_second_different_offset(void)
{
	struct ela_uboot_env_candidate *cands = NULL;
	size_t count = 0;

	ela_uboot_env_add_or_merge_candidate(&cands, &count, 0x1000, true, false);
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_add_or_merge_candidate(
		&cands, &count, 0x2000, false, true));
	ELA_ASSERT_INT_EQ(2, (int)count);
	free(cands);
}

static void test_merge_same_offset_ors_flags(void)
{
	struct ela_uboot_env_candidate *cands = NULL;
	size_t count = 0;

	ela_uboot_env_add_or_merge_candidate(&cands, &count, 0x1000, true, false);
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_add_or_merge_candidate(
		&cands, &count, 0x1000, false, true));
	ELA_ASSERT_INT_EQ(1, (int)count);
	ELA_ASSERT_TRUE(cands[0].crc_standard);
	ELA_ASSERT_TRUE(cands[0].crc_redundant);
	free(cands);
}

static void test_merge_flags_preserved_when_already_set(void)
{
	struct ela_uboot_env_candidate *cands = NULL;
	size_t count = 0;

	ela_uboot_env_add_or_merge_candidate(&cands, &count, 0x1000, true, true);
	ela_uboot_env_add_or_merge_candidate(&cands, &count, 0x1000, false, false);
	ELA_ASSERT_TRUE(cands[0].crc_standard);
	ELA_ASSERT_TRUE(cands[0].crc_redundant);
	free(cands);
}

/* =========================================================================
 * ela_uboot_env_is_http_write_source
 * ====================================================================== */

static void test_http_source_null(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_is_http_write_source(NULL));
}

static void test_http_source_empty(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_is_http_write_source(""));
}

static void test_http_source_http(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_is_http_write_source("http://example.com/script"));
}

static void test_http_source_https(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_is_http_write_source("https://example.com/script"));
}

static void test_http_source_ftp(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_is_http_write_source("ftp://example.com/file"));
}

static void test_http_source_file_path(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_is_http_write_source("/tmp/write.env"));
}

/* =========================================================================
 * ela_uboot_env_should_report_redundant_pair
 * ====================================================================== */

static void test_redundant_zero_erase(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_should_report_redundant_pair(
		0x1000, 0x2000, 0, 1));
}

static void test_redundant_curr_less_than_prev(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_should_report_redundant_pair(
		0x2000, 0x1000, 0x1000, 1));
}

static void test_redundant_exact_erase_gap(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_should_report_redundant_pair(
		0x1000, 0x2000, 0x1000, 2));
}

static void test_redundant_exact_sector_multiple(void)
{
	/* erase=0x1000, sectors=2 → expected gap = 0x2000 */
	ELA_ASSERT_TRUE(ela_uboot_env_should_report_redundant_pair(
		0x1000, 0x3000, 0x1000, 2));
}

static void test_redundant_wrong_gap(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_should_report_redundant_pair(
		0x1000, 0x2800, 0x1000, 2));
}

static void test_redundant_zero_sector_count_uses_one(void)
{
	/* sector_count=0 → treated as 1 → expected = erase_size */
	ELA_ASSERT_TRUE(ela_uboot_env_should_report_redundant_pair(
		0x1000, 0x2000, 0x1000, 0));
}

static void test_redundant_sector_count_one_matches_erase(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_should_report_redundant_pair(
		0x0, 0x1000, 0x1000, 1));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_env_scan_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "merge_null_cands",                  test_merge_null_cands },
		{ "merge_null_count",                  test_merge_null_count },
		{ "merge_fresh_add",                   test_merge_fresh_add },
		{ "merge_second_different_offset",     test_merge_second_different_offset },
		{ "merge_same_offset_ors_flags",       test_merge_same_offset_ors_flags },
		{ "merge_flags_preserved",             test_merge_flags_preserved_when_already_set },
		{ "http_source_null",                  test_http_source_null },
		{ "http_source_empty",                 test_http_source_empty },
		{ "http_source_http",                  test_http_source_http },
		{ "http_source_https",                 test_http_source_https },
		{ "http_source_ftp",                   test_http_source_ftp },
		{ "http_source_file_path",             test_http_source_file_path },
		{ "redundant_zero_erase",              test_redundant_zero_erase },
		{ "redundant_curr_less_prev",          test_redundant_curr_less_than_prev },
		{ "redundant_exact_erase_gap",         test_redundant_exact_erase_gap },
		{ "redundant_sector_multiple",         test_redundant_exact_sector_multiple },
		{ "redundant_wrong_gap",               test_redundant_wrong_gap },
		{ "redundant_zero_sector_count",       test_redundant_zero_sector_count_uses_one },
		{ "redundant_sector_one_erase",        test_redundant_sector_count_one_matches_erase },
	};
	return ela_run_test_suite("uboot_env_scan_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
