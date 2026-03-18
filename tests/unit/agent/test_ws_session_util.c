// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ws_client.h"
#include "../../../agent/net/ws_session_util.h"
#include "../../../agent/net/ws_frame_util.h"

#include <string.h>

static void test_ws_handshake_validation_accepts_101_and_reports_errors(void)
{
	char errbuf[256];

	ELA_ASSERT_TRUE(ela_ws_response_headers_complete("HTTP/1.1 101 Switching Protocols\r\n\r\n",
							 strlen("HTTP/1.1 101 Switching Protocols\r\n\r\n")));
	ELA_ASSERT_FALSE(ela_ws_response_headers_complete("HTTP/1.1 101 Switching Protocols\r\n",
							  strlen("HTTP/1.1 101 Switching Protocols\r\n")));
	ELA_ASSERT_TRUE(ela_ws_handshake_response_is_unauthorized("HTTP/1.1 401 Unauthorized\r\n\r\n"));
	ELA_ASSERT_FALSE(ela_ws_handshake_response_is_unauthorized("HTTP/1.1 500 Server Error\r\n\r\n"));
	ELA_ASSERT_INT_EQ(0, ela_ws_validate_handshake_response("HTTP/1.1 101 Switching Protocols\r\n\r\n",
							errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_ws_validate_handshake_response("HTTP/1.1 401 Unauthorized\r\n\r\n",
							 errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "401 Unauthorized") != NULL);
}

static void test_ws_heartbeat_ack_builder_and_frame_classification(void)
{
	char ack[160];
	struct ela_ws_frame_action action;

	ELA_ASSERT_INT_EQ(0, ela_ws_build_heartbeat_ack("Thu Mar 18 12:00:00 UTC 2026", ack, sizeof(ack)));
	ELA_ASSERT_TRUE(strstr(ack, "\"_type\":\"heartbeat_ack\"") != NULL);

	ela_ws_classify_incoming_frame(ELA_WS_OPCODE_TEXT, "{\"_type\":\"heartbeat\"}", 23, &action);
	ELA_ASSERT_INT_EQ(1, action.send_heartbeat_ack);
	ELA_ASSERT_INT_EQ(0, action.forward_to_repl);

	ela_ws_classify_incoming_frame(ELA_WS_OPCODE_PING, "", 0, &action);
	ELA_ASSERT_INT_EQ(1, action.send_pong);
	ELA_ASSERT_INT_EQ(0, action.terminate_session);

	ela_ws_classify_incoming_frame(ELA_WS_OPCODE_CLOSE, "", 0, &action);
	ELA_ASSERT_INT_EQ(1, action.terminate_session);
}

static void test_ws_zero_mask_control_frame_builder_emits_expected_bytes(void)
{
	uint8_t frame[6];
	size_t frame_len = 0;

	ELA_ASSERT_INT_EQ(0, ela_ws_build_zero_mask_control_frame(ELA_WS_OPCODE_PONG, frame, &frame_len));
	ELA_ASSERT_INT_EQ(6, frame_len);
	ELA_ASSERT_INT_EQ(0x8A, frame[0]);
	ELA_ASSERT_INT_EQ(0x80, frame[1]);
	ELA_ASSERT_INT_EQ(0, frame[2]);
	ELA_ASSERT_INT_EQ(0, frame[5]);
}

static void test_ws_ping_and_loop_policy_helpers(void)
{
	uint8_t frame[6];
	size_t frame_len = 0;

	ELA_ASSERT_INT_EQ(0, ela_ws_build_ping_frame(frame, &frame_len));
	ELA_ASSERT_INT_EQ(6, frame_len);
	ELA_ASSERT_INT_EQ(0x89, frame[0]);
	ELA_ASSERT_INT_EQ(0x80, frame[1]);
	ELA_ASSERT_TRUE(ela_ws_child_wait_exited(42));
	ELA_ASSERT_FALSE(ela_ws_child_wait_exited(0));
	ELA_ASSERT_TRUE(ela_ws_child_output_should_break(0));
	ELA_ASSERT_TRUE(ela_ws_child_output_should_break(-1));
	ELA_ASSERT_FALSE(ela_ws_child_output_should_break(7));
	ELA_ASSERT_INT_EQ(ELA_WS_EXIT_CLEAN, ela_ws_interactive_exit_code(1));
	ELA_ASSERT_INT_EQ(0, ela_ws_interactive_exit_code(0));
}

int run_ws_session_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "ws_handshake_validation_accepts_101_and_reports_errors", test_ws_handshake_validation_accepts_101_and_reports_errors },
		{ "ws_heartbeat_ack_builder_and_frame_classification", test_ws_heartbeat_ack_builder_and_frame_classification },
		{ "ws_zero_mask_control_frame_builder_emits_expected_bytes", test_ws_zero_mask_control_frame_builder_emits_expected_bytes },
		{ "ws_ping_and_loop_policy_helpers", test_ws_ping_and_loop_policy_helpers },
	};

	return ela_run_test_suite("ws_session_util", cases, sizeof(cases) / sizeof(cases[0]));
}
