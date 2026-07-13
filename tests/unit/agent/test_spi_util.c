// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/spi/spi_util.h"
#include "test_harness.h"

#include <string.h>

static void test_selects_largest_mtd(void)
{
	struct ela_spi_mtd_candidate items[] = {
		{ .spi_name = "spi0.0", .mtd_name = "boot", .mtd_index = 1, .size = 0x100000 },
		{ .spi_name = "spi0.0", .mtd_name = "flash", .mtd_index = 0, .size = 0x1000000 },
		{ .spi_name = "spi0.0", .mtd_name = "env", .mtd_index = 2, .size = 0x20000 },
	};
	char errbuf[128];
	size_t selected = 99;

	ELA_ASSERT_INT_EQ(0, ela_spi_select_dump_candidate(
		items, 3, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, selected);
}

static void test_rejects_ambiguous_largest_mtd(void)
{
	struct ela_spi_mtd_candidate items[] = {
		{ .spi_name = "spi0.0", .mtd_name = "flash0", .size = 0x1000000 },
		{ .spi_name = "spi1.0", .mtd_name = "flash1", .size = 0x1000000 },
	};
	char errbuf[128];
	size_t selected;

	ELA_ASSERT_INT_EQ(-1, ela_spi_select_dump_candidate(
		items, 2, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Multiple") != NULL);
}

static void test_rejects_missing_or_zero_sized_mtd(void)
{
	struct ela_spi_mtd_candidate zero = {0};
	char errbuf[128];
	size_t selected;

	ELA_ASSERT_INT_EQ(-1, ela_spi_select_dump_candidate(
		NULL, 0, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "No SPI-backed") != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_spi_select_dump_candidate(
		&zero, 1, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "no readable size") != NULL);
}

static void test_parse_device_index(void)
{
	char errbuf[128];
	size_t index = 99;

	ELA_ASSERT_INT_EQ(0, ela_spi_parse_device_index(
		"0", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(0, index);
	ELA_ASSERT_INT_EQ(0, ela_spi_parse_device_index(
		"42", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(42, index);
	ELA_ASSERT_INT_EQ(-1, ela_spi_parse_device_index(
		"-1", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_spi_parse_device_index(
		"1x", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_spi_parse_device_index(
		"4294967296", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_spi_parse_device_index(
		"", &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_spi_parse_device_index(
		NULL, &index, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_spi_parse_device_index(
		"1", NULL, errbuf, sizeof(errbuf)));
}

int run_spi_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "spi/selects_largest_mtd", test_selects_largest_mtd },
		{ "spi/rejects_ambiguous_largest_mtd", test_rejects_ambiguous_largest_mtd },
		{ "spi/rejects_missing_or_zero_sized_mtd", test_rejects_missing_or_zero_sized_mtd },
		{ "spi/parse_device_index", test_parse_device_index },
	};

	return ela_run_test_suite("spi_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
