// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef NET_WS_SESSION_UTIL_H
#define NET_WS_SESSION_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Application close code (RFC 6455 private range, 4000-4999) the terminal API
 * sends when it displaces this MAC's session with a newer connection. On
 * receipt the agent exits its --remote loop instead of reconnecting, so
 * duplicate daemons do not fight over the single per-MAC session slot.
 */
#define ELA_WS_CLOSE_SUPERSEDED 4000

struct ela_ws_frame_action {
	int terminate_session;
	/* Set with terminate_session when the peer's CLOSE carried a code that
	 * means "do not reconnect" (see ELA_WS_CLOSE_SUPERSEDED). */
	int no_reconnect;
	int send_pong;
	int send_heartbeat_ack;
	int forward_to_repl;
};

int ela_ws_validate_handshake_response(const char *response,
				       char *errbuf,
				       size_t errbuf_len);
bool ela_ws_response_headers_complete(const char *response, size_t response_len);
bool ela_ws_handshake_response_is_unauthorized(const char *response);
int ela_ws_build_heartbeat_ack(const char *date_str, char *out, size_t out_sz);
void ela_ws_classify_incoming_frame(uint8_t opcode,
				    const char *payload,
				    size_t payload_len,
				    struct ela_ws_frame_action *out);
int ela_ws_build_ping_frame(uint8_t frame[6], size_t *frame_len_out);
int ela_ws_build_zero_mask_control_frame(uint8_t opcode,
					 uint8_t frame[6],
					 size_t *frame_len_out);
bool ela_ws_child_wait_exited(int waitpid_result);
bool ela_ws_child_output_should_break(ssize_t read_len);
int ela_ws_interactive_exit_code(int child_exited);

#endif
