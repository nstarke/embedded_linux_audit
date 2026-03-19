// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ws_client_runtime_util.h"
#include "../../../agent/net/ws_frame_util.h"
#include "../../../agent/net/ws_client.h"

#include <string.h>

struct fake_ws_dispatch_state {
	int write_calls;
	int pong_calls;
	int ack_calls;
	int fail_write;
	char payload[128];
};

static int fake_write_repl(void *ctx, const char *payload, size_t payload_len)
{
	struct fake_ws_dispatch_state *state = (struct fake_ws_dispatch_state *)ctx;
	size_t copy_len = payload_len;

	state->write_calls++;
	if (state->fail_write)
		return -1;
	if (copy_len >= sizeof(state->payload))
		copy_len = sizeof(state->payload) - 1;
	memcpy(state->payload, payload, copy_len);
	state->payload[copy_len] = '\0';
	return 0;
}

static int fake_send_pong(void *ctx)
{
	struct fake_ws_dispatch_state *state = (struct fake_ws_dispatch_state *)ctx;

	state->pong_calls++;
	return 0;
}

static int fake_send_ack(void *ctx)
{
	struct fake_ws_dispatch_state *state = (struct fake_ws_dispatch_state *)ctx;

	state->ack_calls++;
	return 0;
}

static void test_ws_client_runtime_formats_handshake_errors(void)
{
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_ws_format_handshake_error(
		"HTTP/1.1 101 Switching Protocols\r\n\r\n", errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("", errbuf);

	ELA_ASSERT_INT_EQ(-1, ela_ws_format_handshake_error(
		"HTTP/1.1 401 Unauthorized\r\n\r\n", errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "401 Unauthorized") != NULL);
	ELA_ASSERT_TRUE(strstr(errbuf, "/tmp/ela.key") != NULL);

	ELA_ASSERT_INT_EQ(-1, ela_ws_format_handshake_error(
		"HTTP/1.1 500 Server Error\r\n\r\n", errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "unexpected response") != NULL);
}

static void test_ws_client_runtime_dispatches_frames(void)
{
	struct fake_ws_dispatch_state state;
	struct ela_ws_runtime_dispatch_ops ops = {
		.write_repl_fn = fake_write_repl,
		.send_pong_fn = fake_send_pong,
		.send_heartbeat_ack_fn = fake_send_ack,
	};

	memset(&state, 0, sizeof(state));
	ELA_ASSERT_INT_EQ(0, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_TEXT, "hello", 5, &ops, &state));
	ELA_ASSERT_INT_EQ(1, state.write_calls);
	ELA_ASSERT_STR_EQ("hello", state.payload);

	memset(&state, 0, sizeof(state));
	ELA_ASSERT_INT_EQ(0, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_PING, "", 0, &ops, &state));
	ELA_ASSERT_INT_EQ(1, state.pong_calls);

	memset(&state, 0, sizeof(state));
	ELA_ASSERT_INT_EQ(0, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_TEXT, "{\"_type\":\"heartbeat\"}", 23, &ops, &state));
	ELA_ASSERT_INT_EQ(1, state.ack_calls);

	ELA_ASSERT_INT_EQ(1, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_CLOSE, "", 0, &ops, &state));

	memset(&state, 0, sizeof(state));
	state.fail_write = 1;
	ELA_ASSERT_INT_EQ(-1, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_TEXT, "broken", 6, &ops, &state));
}

static void test_ws_client_runtime_reconnect_policy(void)
{
	ELA_ASSERT_TRUE(ela_ws_should_reconnect_after_disconnect(0));
	ELA_ASSERT_FALSE(ela_ws_should_reconnect_after_disconnect(ELA_WS_EXIT_CLEAN));
}

int run_ws_client_runtime_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "ws_client_runtime_formats_handshake_errors", test_ws_client_runtime_formats_handshake_errors },
		{ "ws_client_runtime_dispatches_frames", test_ws_client_runtime_dispatches_frames },
		{ "ws_client_runtime_reconnect_policy", test_ws_client_runtime_reconnect_policy },
	};

	return ela_run_test_suite("ws_client_runtime_util", cases, sizeof(cases) / sizeof(cases[0]));
}
