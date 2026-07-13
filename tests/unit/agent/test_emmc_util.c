// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/emmc/emmc_util.h"
#include "test_harness.h"

#include <stdint.h>
#include <string.h>

static void test_selects_unique_largest_device(void)
{
	struct ela_emmc_candidate items[] = {
		{ .disk_name = "mmcblk0", .size = 8 },
		{ .disk_name = "mmcblk1", .size = 16 },
	};
	char errbuf[128] = { 0 };
	size_t selected = 99;

	ELA_ASSERT_INT_EQ(0, ela_emmc_select_dump_candidate(
		items, 2, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, selected);
}

static void test_rejects_ambiguous_or_missing_devices(void)
{
	struct ela_emmc_candidate tied[] = {
		{ .disk_name = "mmcblk0", .size = 16 },
		{ .disk_name = "mmcblk1", .size = 16 },
	};
	char errbuf[128] = { 0 };
	size_t selected = 0;

	ELA_ASSERT_INT_EQ(-1, ela_emmc_select_dump_candidate(
		tied, 2, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Multiple") != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_emmc_select_dump_candidate(
		tied, 0, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "No readable") != NULL);
}

static void test_parses_decimal_device_index(void)
{
	char errbuf[128] = { 0 };
	size_t index = 99;

	ELA_ASSERT_INT_EQ(0, ela_emmc_parse_device_index(
		"12", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(12, index);
	ELA_ASSERT_INT_EQ(-1, ela_emmc_parse_device_index(
		"", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_emmc_parse_device_index(
		"-1", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_emmc_parse_device_index(
		"1x", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_emmc_parse_device_index(
		"4294967296", &index, errbuf, sizeof(errbuf)));
}

int run_emmc_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "select/unique-largest", test_selects_unique_largest_device },
		{ "select/ambiguous-missing", test_rejects_ambiguous_or_missing_devices },
		{ "parse/device-index", test_parses_decimal_device_index },
	};

	return ela_run_test_suite("emmc_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
