// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/linux/linux_dmesg_util.h"

#include <string.h>

static void test_dmesg_determine_mode_rejects_conflicting_options(void)
{
	enum ela_dmesg_mode mode = ELA_DMESG_MODE_ALL;
	char errbuf[128];

	ELA_ASSERT_INT_EQ(-1, ela_dmesg_determine_mode(5, 5, &mode, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "--head or --tail") != NULL);
}

static void test_dmesg_determine_mode_selects_expected_mode(void)
{
	enum ela_dmesg_mode mode = ELA_DMESG_MODE_ALL;

	ELA_ASSERT_INT_EQ(0, ela_dmesg_determine_mode(3, 0, &mode, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_DMESG_MODE_HEAD, mode);
	ELA_ASSERT_INT_EQ(0, ela_dmesg_determine_mode(0, 4, &mode, NULL, 0));
	ELA_ASSERT_INT_EQ(ELA_DMESG_MODE_TAIL, mode);
}

static void test_dmesg_tail_window_computes_ring_order(void)
{
	size_t start = 0;
	size_t emit = 0;

	ela_dmesg_tail_window(2, 5, &start, &emit);
	ELA_ASSERT_INT_EQ(0, start);
	ELA_ASSERT_INT_EQ(2, emit);

	ela_dmesg_tail_window(7, 5, &start, &emit);
	ELA_ASSERT_INT_EQ(2, start);
	ELA_ASSERT_INT_EQ(5, emit);
}

int run_linux_dmesg_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "dmesg_determine_mode_rejects_conflicting_options", test_dmesg_determine_mode_rejects_conflicting_options },
		{ "dmesg_determine_mode_selects_expected_mode", test_dmesg_determine_mode_selects_expected_mode },
		{ "dmesg_tail_window_computes_ring_order", test_dmesg_tail_window_computes_ring_order },
	};

	return ela_run_test_suite("linux_dmesg_util", cases, sizeof(cases) / sizeof(cases[0]));
}
