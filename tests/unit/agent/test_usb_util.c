// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/usb/usb_util.h"
#include "test_harness.h"

#include <string.h>

static void test_parse_u32(void)
{
	uint32_t value = 0;
	char errbuf[64] = { 0 };

	ELA_ASSERT_INT_EQ(0, ela_usb_parse_u32("17", &value, "index",
					      errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(17, value);
	ELA_ASSERT_INT_EQ(-1, ela_usb_parse_u32("-1", &value, "index",
					       errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_usb_parse_u32("1x", &value, "index",
					       errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_usb_parse_u32("4294967296", &value, "index",
					       errbuf, sizeof(errbuf)));
}

static void test_select_single_non_root(void)
{
	struct ela_usb_candidate items[] = {
		{ .busnum = 1, .devnum = 1, .parent_devnum = 0 },
		{ .busnum = 1, .devnum = 2, .parent_devnum = 1 },
	};
	size_t selected = 99;
	char errbuf[96] = { 0 };

	ELA_ASSERT_INT_EQ(0, ela_usb_select_descriptor_candidate(
		items, 2, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, selected);
}

static void test_reject_ambiguous_or_root_only(void)
{
	struct ela_usb_candidate items[] = {
		{ .devnum = 1, .parent_devnum = 0 },
		{ .devnum = 2, .parent_devnum = 1 },
		{ .devnum = 3, .parent_devnum = 1 },
	};
	size_t selected = 0;
	char errbuf[96] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_usb_select_descriptor_candidate(
		items, 3, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Multiple") != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_usb_select_descriptor_candidate(
		items, 1, &selected, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "No non-root") != NULL);
}

int run_usb_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "parse/u32", test_parse_u32 },
		{ "select/single", test_select_single_non_root },
		{ "select/ambiguous-root", test_reject_ambiguous_or_root_only },
	};

	return ela_run_test_suite("usb_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
