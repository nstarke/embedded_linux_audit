// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ws_frame_util.h"

#include <stdlib.h>

static void test_ws_frame_builder_and_parser_round_trip(void)
{
	const uint8_t mask[4] = { 0x12, 0x34, 0x56, 0x78 };
	uint8_t *frame = NULL;
	size_t frame_len = 0;
	uint8_t opcode = 0;
	char payload[64];

	ELA_ASSERT_INT_EQ(0, ela_ws_build_masked_frame(ELA_WS_OPCODE_TEXT, mask, "hello", 5, &frame, &frame_len));
	ELA_ASSERT_TRUE(frame_len > 6);
	ELA_ASSERT_INT_EQ(5, ela_ws_parse_frame_bytes(frame, frame_len, &opcode, payload, sizeof(payload)));
	ELA_ASSERT_INT_EQ(ELA_WS_OPCODE_TEXT, opcode);
	ELA_ASSERT_STR_EQ("hello", payload);
	free(frame);
}

static void test_ws_frame_parser_truncates_to_buffer(void)
{
	const uint8_t frame[] = { 0x81, 0x03, 'a', 'b', 'c' };
	uint8_t opcode = 0;
	char payload[3];

	ELA_ASSERT_INT_EQ(2, ela_ws_parse_frame_bytes(frame, sizeof(frame), &opcode, payload, sizeof(payload)));
	ELA_ASSERT_STR_EQ("ab", payload);
}

int run_ws_frame_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "ws_frame_builder_and_parser_round_trip", test_ws_frame_builder_and_parser_round_trip },
		{ "ws_frame_parser_truncates_to_buffer", test_ws_frame_parser_truncates_to_buffer },
	};

	return ela_run_test_suite("ws_frame_util", cases, sizeof(cases) / sizeof(cases[0]));
}
