// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/orom/orom_kmod_util.h"
#include "test_harness.h"

#include <string.h>

static void test_selects_unique_largest_rom(void)
{
	struct ela_orom_kmod_candidate items[] = {
		{ .device = 1, .size = 65536 },
		{ .device = 2, .size = 131072 },
	};
	size_t selected = 99;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(0, ela_orom_kmod_select_candidate(
		items, 2, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, selected);
}

static void test_rejects_ambiguous_or_missing_roms(void)
{
	struct ela_orom_kmod_candidate tied[] = {
		{ .device = 1, .size = 65536 },
		{ .device = 2, .size = 65536 },
	};
	size_t selected = 0;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_orom_kmod_select_candidate(
		tied, 2, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Multiple") != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_orom_kmod_select_candidate(
		tied, 0, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "No kernel-mappable") != NULL);
}

static void test_parses_decimal_index(void)
{
	size_t index = 99;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(0, ela_orom_kmod_parse_index(
		"7", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(7, index);
	ELA_ASSERT_INT_EQ(-1, ela_orom_kmod_parse_index(
		"-1", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_orom_kmod_parse_index(
		"1x", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_orom_kmod_parse_index(
		"4294967296", &index, errbuf, sizeof(errbuf)));
}

int run_orom_kmod_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "select/unique-largest", test_selects_unique_largest_rom },
		{ "select/ambiguous-missing", test_rejects_ambiguous_or_missing_roms },
		{ "parse/index", test_parses_decimal_index },
	};

	return ela_run_test_suite("orom_kmod_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
