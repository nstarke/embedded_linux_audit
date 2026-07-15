// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_bt_util.h"
#include "test_harness.h"

static void test_parse_hci_dev(void)
{
	int idx = -1;

	ELA_ASSERT_TRUE(bt_parse_hci_dev("hci0", &idx) == 0);
	ELA_ASSERT_TRUE(idx == 0);
	ELA_ASSERT_TRUE(bt_parse_hci_dev("hci1", &idx) == 0);
	ELA_ASSERT_TRUE(idx == 1);
	ELA_ASSERT_TRUE(bt_parse_hci_dev("hci12", &idx) == 0);
	ELA_ASSERT_TRUE(idx == 12);
	ELA_ASSERT_TRUE(bt_parse_hci_dev("hci65535", &idx) == 0);
	ELA_ASSERT_TRUE(idx == 65535);

	/* rejected: no prefix, no number, non-digit, out of u16 range, junk */
	ELA_ASSERT_TRUE(bt_parse_hci_dev("hci", &idx) != 0);
	ELA_ASSERT_TRUE(bt_parse_hci_dev("hci0x", &idx) != 0);
	ELA_ASSERT_TRUE(bt_parse_hci_dev("bt0", &idx) != 0);
	ELA_ASSERT_TRUE(bt_parse_hci_dev("hcia", &idx) != 0);
	ELA_ASSERT_TRUE(bt_parse_hci_dev("hci-1", &idx) != 0);
	ELA_ASSERT_TRUE(bt_parse_hci_dev("hci65536", &idx) != 0);
	ELA_ASSERT_TRUE(bt_parse_hci_dev("hci999999", &idx) != 0);
	ELA_ASSERT_TRUE(bt_parse_hci_dev("", &idx) != 0);
	ELA_ASSERT_TRUE(bt_parse_hci_dev(NULL, &idx) != 0);
}

int run_linux_bt_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "parse/hci_dev", test_parse_hci_dev },
	};

	return ela_run_test_suite("linux_bt_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
