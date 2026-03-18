// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ws_recv_util.h"

static void test_ws_recv_truncation_helpers_compute_copy_and_skip_lengths(void)
{
	ELA_ASSERT_INT_EQ(5, ela_ws_payload_copy_len(5, 32));
	ELA_ASSERT_INT_EQ(0, ela_ws_payload_skip_len(5, 32));
	ELA_ASSERT_INT_EQ(9, ela_ws_payload_copy_len(20, 10));
	ELA_ASSERT_INT_EQ(11, ela_ws_payload_skip_len(20, 10));
}

int run_ws_recv_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "ws_recv_truncation_helpers_compute_copy_and_skip_lengths", test_ws_recv_truncation_helpers_compute_copy_and_skip_lengths },
	};

	return ela_run_test_suite("ws_recv_util", cases, sizeof(cases) / sizeof(cases[0]));
}
