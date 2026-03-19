// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ws_interactive_util.h"

static void test_ws_interactive_default_mask_key(void)
{
	uint8_t mask[4] = {0};

	ela_ws_default_mask_key(mask);
	ELA_ASSERT_INT_EQ(0xDE, mask[0]);
	ELA_ASSERT_INT_EQ(0xAD, mask[1]);
	ELA_ASSERT_INT_EQ(0xBE, mask[2]);
	ELA_ASSERT_INT_EQ(0xEF, mask[3]);
}

static void test_ws_interactive_socket_readable_helper(void)
{
	ELA_ASSERT_TRUE(ela_ws_socket_readable(1, false, 0));
	ELA_ASSERT_TRUE(ela_ws_socket_readable(0, true, 3));
	ELA_ASSERT_FALSE(ela_ws_socket_readable(0, false, 5));
	ELA_ASSERT_FALSE(ela_ws_socket_readable(0, true, 0));
}

int run_ws_interactive_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "ws_interactive_default_mask_key", test_ws_interactive_default_mask_key },
		{ "ws_interactive_socket_readable_helper", test_ws_interactive_socket_readable_helper },
	};

	return ela_run_test_suite("ws_interactive_util", cases, sizeof(cases) / sizeof(cases[0]));
}
