// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/nand/nand_util.h"
#include "test_harness.h"

#include <string.h>

static void test_selects_largest_nand(void)
{
	struct ela_nand_candidate items[] = {
		{ .mtd_name = "boot", .mtd_index = 1, .size = 0x100000 },
		{ .mtd_name = "whole-nand", .mtd_index = 0, .size = 0x8000000 },
		{ .mtd_name = "rootfs", .mtd_index = 2, .size = 0x4000000 },
	};
	char errbuf[128];
	size_t selected = 99;

	ELA_ASSERT_INT_EQ(0, ela_nand_select_dump_candidate(
		items, 3, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, selected);
}

static void test_rejects_ambiguous_or_missing_nand(void)
{
	struct ela_nand_candidate items[] = {
		{ .mtd_name = "nand0", .size = 0x8000000 },
		{ .mtd_name = "nand1", .size = 0x8000000 },
	};
	char errbuf[128];
	size_t selected;

	ELA_ASSERT_INT_EQ(-1, ela_nand_select_dump_candidate(
		items, 2, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Multiple") != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_nand_select_dump_candidate(
		NULL, 0, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "No NAND") != NULL);
}

static void test_parse_nand_index(void)
{
	char errbuf[128];
	size_t index;

	ELA_ASSERT_INT_EQ(0, ela_nand_parse_device_index(
		"12", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(12, index);
	ELA_ASSERT_INT_EQ(-1, ela_nand_parse_device_index(
		"-1", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_nand_parse_device_index(
		"12x", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_nand_parse_device_index(
		"4294967296", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_nand_parse_device_index(
		NULL, &index, errbuf, sizeof(errbuf)));
}

int run_nand_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "nand/selects_largest", test_selects_largest_nand },
		{ "nand/rejects_ambiguous_or_missing", test_rejects_ambiguous_or_missing_nand },
		{ "nand/parse_index", test_parse_nand_index },
	};

	return ela_run_test_suite("nand_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
