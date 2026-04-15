// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ws_client_runtime_util.h"
#include "../../../agent/net/ws_frame_util.h"
#include "../../../agent/net/ws_client.h"
#include "../../../agent/net/ws_url_util.h"

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

/* -------------------------------------------------------------------------
 * ela_ws_format_handshake_error
 * ---------------------------------------------------------------------- */

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

static void test_ws_format_handshake_error_null_response(void)
{
	char errbuf[256];

	/* NULL response is treated as malformed */
	ELA_ASSERT_INT_EQ(-1, ela_ws_format_handshake_error(NULL, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "malformed") != NULL);
}

static void test_ws_format_handshake_error_null_errbuf(void)
{
	/* Should return the right code without writing to NULL */
	ELA_ASSERT_INT_EQ(0, ela_ws_format_handshake_error(
		"HTTP/1.1 101 Switching Protocols\r\n\r\n", NULL, 256));
	ELA_ASSERT_INT_EQ(-1, ela_ws_format_handshake_error(
		"HTTP/1.1 500 Error\r\n\r\n", NULL, 256));
}

static void test_ws_format_handshake_error_zero_errbuf_len(void)
{
	char errbuf[256];

	errbuf[0] = 'X';
	/* Zero len: no write should occur */
	ELA_ASSERT_INT_EQ(-1, ela_ws_format_handshake_error(
		"HTTP/1.1 500 Error\r\n\r\n", errbuf, 0));
	ELA_ASSERT_INT_EQ('X', errbuf[0]);
}

static void test_ws_format_handshake_error_non_http_response(void)
{
	char errbuf[256];

	/* Garbage response: not HTTP/1.1 */
	ELA_ASSERT_INT_EQ(-1, ela_ws_format_handshake_error(
		"garbage\r\n\r\n", errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "malformed") != NULL);
}

/* -------------------------------------------------------------------------
 * ela_ws_dispatch_incoming_frame
 * ---------------------------------------------------------------------- */

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

static void test_ws_dispatch_null_ops(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_TEXT, "hi", 2, NULL, NULL));
}

static void test_ws_dispatch_null_write_fn_for_text(void)
{
	struct fake_ws_dispatch_state state;
	struct ela_ws_runtime_dispatch_ops ops = {
		.write_repl_fn = NULL,
		.send_pong_fn = fake_send_pong,
		.send_heartbeat_ack_fn = fake_send_ack,
	};

	memset(&state, 0, sizeof(state));
	ELA_ASSERT_INT_EQ(-1, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_TEXT, "data", 4, &ops, &state));
}

static void test_ws_dispatch_null_pong_fn_for_ping(void)
{
	struct fake_ws_dispatch_state state;
	struct ela_ws_runtime_dispatch_ops ops = {
		.write_repl_fn = fake_write_repl,
		.send_pong_fn = NULL,
		.send_heartbeat_ack_fn = fake_send_ack,
	};

	memset(&state, 0, sizeof(state));
	ELA_ASSERT_INT_EQ(-1, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_PING, "", 0, &ops, &state));
}

static void test_ws_dispatch_null_ack_fn_for_heartbeat(void)
{
	struct fake_ws_dispatch_state state;
	struct ela_ws_runtime_dispatch_ops ops = {
		.write_repl_fn = fake_write_repl,
		.send_pong_fn = fake_send_pong,
		.send_heartbeat_ack_fn = NULL,
	};

	memset(&state, 0, sizeof(state));
	ELA_ASSERT_INT_EQ(-1, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_TEXT, "{\"_type\":\"heartbeat\"}", 20, &ops, &state));
}

static void test_ws_dispatch_binary_frame_ignored(void)
{
	struct fake_ws_dispatch_state state;
	struct ela_ws_runtime_dispatch_ops ops = {
		.write_repl_fn = fake_write_repl,
		.send_pong_fn = fake_send_pong,
		.send_heartbeat_ack_fn = fake_send_ack,
	};

	memset(&state, 0, sizeof(state));
	/* opcode 0x02 = BINARY — not handled, no action */
	ELA_ASSERT_INT_EQ(0, ela_ws_dispatch_incoming_frame(
		0x02, "data", 4, &ops, &state));
	ELA_ASSERT_INT_EQ(0, state.write_calls);
	ELA_ASSERT_INT_EQ(0, state.pong_calls);
	ELA_ASSERT_INT_EQ(0, state.ack_calls);
}

static void test_ws_dispatch_pong_frame_ignored(void)
{
	struct fake_ws_dispatch_state state;
	struct ela_ws_runtime_dispatch_ops ops = {
		.write_repl_fn = fake_write_repl,
		.send_pong_fn = fake_send_pong,
		.send_heartbeat_ack_fn = fake_send_ack,
	};

	memset(&state, 0, sizeof(state));
	ELA_ASSERT_INT_EQ(0, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_PONG, "", 0, &ops, &state));
	ELA_ASSERT_INT_EQ(0, state.write_calls + state.pong_calls + state.ack_calls);
}

static void test_ws_dispatch_text_empty_payload_ignored(void)
{
	struct fake_ws_dispatch_state state;
	struct ela_ws_runtime_dispatch_ops ops = {
		.write_repl_fn = fake_write_repl,
		.send_pong_fn = fake_send_pong,
		.send_heartbeat_ack_fn = fake_send_ack,
	};

	memset(&state, 0, sizeof(state));
	/* TEXT with zero-length payload: classify produces no action */
	ELA_ASSERT_INT_EQ(0, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_TEXT, "", 0, &ops, &state));
	ELA_ASSERT_INT_EQ(0, state.write_calls);
}

static void test_ws_dispatch_text_null_payload_ignored(void)
{
	struct fake_ws_dispatch_state state;
	struct ela_ws_runtime_dispatch_ops ops = {
		.write_repl_fn = fake_write_repl,
		.send_pong_fn = fake_send_pong,
		.send_heartbeat_ack_fn = fake_send_ack,
	};

	memset(&state, 0, sizeof(state));
	/* TEXT with NULL payload: classify produces no action */
	ELA_ASSERT_INT_EQ(0, ela_ws_dispatch_incoming_frame(
		ELA_WS_OPCODE_TEXT, NULL, 0, &ops, &state));
	ELA_ASSERT_INT_EQ(0, state.write_calls);
}

/* -------------------------------------------------------------------------
 * ela_ws_should_reconnect_after_disconnect
 * ---------------------------------------------------------------------- */

static void test_ws_client_runtime_reconnect_policy(void)
{
	ELA_ASSERT_TRUE(ela_ws_should_reconnect_after_disconnect(0));
	ELA_ASSERT_FALSE(ela_ws_should_reconnect_after_disconnect(ELA_WS_EXIT_CLEAN));
}

/* -------------------------------------------------------------------------
 * ela_ws_reconnect_budget_exhausted
 * ---------------------------------------------------------------------- */

/*
 * retry_attempts=0: no retries; the very first failure (failed_attempts=1)
 * must be immediately fatal.
 */
static void test_ws_reconnect_budget_no_retries_exhausted_on_first_failure(void)
{
	ELA_ASSERT_TRUE(ela_ws_reconnect_budget_exhausted(1, 0));
}

/*
 * retry_attempts=5: failures 1-5 are within budget; failure 6 exhausts it.
 * This mirrors the original inner-loop check `failed_attempts > retry_attempts`
 * which allowed exactly retry_attempts reconnect attempts before giving up.
 */
static void test_ws_reconnect_budget_within_budget(void)
{
	ELA_ASSERT_FALSE(ela_ws_reconnect_budget_exhausted(1, 5));
	ELA_ASSERT_FALSE(ela_ws_reconnect_budget_exhausted(3, 5));
	ELA_ASSERT_FALSE(ela_ws_reconnect_budget_exhausted(5, 5));
}

static void test_ws_reconnect_budget_exhausted_at_limit_plus_one(void)
{
	ELA_ASSERT_TRUE(ela_ws_reconnect_budget_exhausted(6, 5));
}

static void test_ws_reconnect_budget_retry_attempts_one(void)
{
	ELA_ASSERT_FALSE(ela_ws_reconnect_budget_exhausted(1, 1));
	ELA_ASSERT_TRUE(ela_ws_reconnect_budget_exhausted(2, 1));
}

/*
 * Regression: wss:// daemonize on arm32-le failed because the TLS connection
 * was established in the parent before fork().  OpenSSL's no-asm/no-threads
 * build on arm32-le is not fork-safe; the inherited SSL state caused the
 * first SSL_write in the child to fail.  The fix is to fork first and connect
 * in the child, so no TLS state crosses the fork boundary.
 *
 * This test verifies that the reconnect budget helper (used by the unified
 * fork-then-connect loop) handles the boundary exactly as the old two-loop
 * structure did: with retry_attempts=N the loop makes N reconnect attempts
 * before declaring exhaustion.
 */
static void test_ws_reconnect_budget_matches_original_loop_semantics(void)
{
	int i;
	int max = 5;

	/* Simulate the inner reconnect loop: increment then check. */
	for (i = 1; i <= max; i++)
		ELA_ASSERT_FALSE(ela_ws_reconnect_budget_exhausted(i, max));

	/* One past the limit must be exhausted. */
	ELA_ASSERT_TRUE(ela_ws_reconnect_budget_exhausted(max + 1, max));
}

/* -------------------------------------------------------------------------
 * ela_is_ws_url
 * ---------------------------------------------------------------------- */

static void test_ws_is_ws_url_valid_ws(void)
{
	ELA_ASSERT_INT_EQ(1, ela_is_ws_url("ws://example.com/path"));
}

static void test_ws_is_ws_url_valid_wss(void)
{
	ELA_ASSERT_INT_EQ(1, ela_is_ws_url("wss://example.com/path"));
}

static void test_ws_is_ws_url_null(void)
{
	ELA_ASSERT_INT_EQ(0, ela_is_ws_url(NULL));
}

static void test_ws_is_ws_url_empty(void)
{
	ELA_ASSERT_INT_EQ(0, ela_is_ws_url(""));
}

static void test_ws_is_ws_url_http(void)
{
	ELA_ASSERT_INT_EQ(0, ela_is_ws_url("http://example.com"));
}

static void test_ws_is_ws_url_https(void)
{
	ELA_ASSERT_INT_EQ(0, ela_is_ws_url("https://example.com"));
}

static void test_ws_is_ws_url_partial_scheme(void)
{
	/* "ws:/example.com" — only one slash, not "ws://" */
	ELA_ASSERT_INT_EQ(0, ela_is_ws_url("ws:/example.com"));
}

int run_ws_client_runtime_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "ws_client_runtime_formats_handshake_errors",      test_ws_client_runtime_formats_handshake_errors },
		{ "ws_format_handshake_error_null_response",         test_ws_format_handshake_error_null_response },
		{ "ws_format_handshake_error_null_errbuf",           test_ws_format_handshake_error_null_errbuf },
		{ "ws_format_handshake_error_zero_errbuf_len",       test_ws_format_handshake_error_zero_errbuf_len },
		{ "ws_format_handshake_error_non_http_response",     test_ws_format_handshake_error_non_http_response },
		{ "ws_client_runtime_dispatches_frames",             test_ws_client_runtime_dispatches_frames },
		{ "ws_dispatch_null_ops",                            test_ws_dispatch_null_ops },
		{ "ws_dispatch_null_write_fn_for_text",              test_ws_dispatch_null_write_fn_for_text },
		{ "ws_dispatch_null_pong_fn_for_ping",               test_ws_dispatch_null_pong_fn_for_ping },
		{ "ws_dispatch_null_ack_fn_for_heartbeat",           test_ws_dispatch_null_ack_fn_for_heartbeat },
		{ "ws_dispatch_binary_frame_ignored",                test_ws_dispatch_binary_frame_ignored },
		{ "ws_dispatch_pong_frame_ignored",                  test_ws_dispatch_pong_frame_ignored },
		{ "ws_dispatch_text_empty_payload_ignored",          test_ws_dispatch_text_empty_payload_ignored },
		{ "ws_dispatch_text_null_payload_ignored",           test_ws_dispatch_text_null_payload_ignored },
		{ "ws_client_runtime_reconnect_policy",              test_ws_client_runtime_reconnect_policy },
		{ "ws_reconnect_budget_no_retries_exhausted_on_first_failure", test_ws_reconnect_budget_no_retries_exhausted_on_first_failure },
		{ "ws_reconnect_budget_within_budget",               test_ws_reconnect_budget_within_budget },
		{ "ws_reconnect_budget_exhausted_at_limit_plus_one", test_ws_reconnect_budget_exhausted_at_limit_plus_one },
		{ "ws_reconnect_budget_retry_attempts_one",          test_ws_reconnect_budget_retry_attempts_one },
		{ "ws_reconnect_budget_matches_original_loop_semantics", test_ws_reconnect_budget_matches_original_loop_semantics },
		{ "ws_is_ws_url_valid_ws",                           test_ws_is_ws_url_valid_ws },
		{ "ws_is_ws_url_valid_wss",                          test_ws_is_ws_url_valid_wss },
		{ "ws_is_ws_url_null",                               test_ws_is_ws_url_null },
		{ "ws_is_ws_url_empty",                              test_ws_is_ws_url_empty },
		{ "ws_is_ws_url_http",                               test_ws_is_ws_url_http },
		{ "ws_is_ws_url_https",                              test_ws_is_ws_url_https },
		{ "ws_is_ws_url_partial_scheme",                     test_ws_is_ws_url_partial_scheme },
	};

	return ela_run_test_suite("ws_client_runtime_util", cases, sizeof(cases) / sizeof(cases[0]));
}
