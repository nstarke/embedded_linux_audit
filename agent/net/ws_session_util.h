// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef NET_WS_SESSION_UTIL_H
#define NET_WS_SESSION_UTIL_H

#include <stddef.h>
#include <stdint.h>

struct ela_ws_frame_action {
	int terminate_session;
	int send_pong;
	int send_heartbeat_ack;
	int forward_to_repl;
};

int ela_ws_validate_handshake_response(const char *response,
				       char *errbuf,
				       size_t errbuf_len);
int ela_ws_build_heartbeat_ack(const char *date_str, char *out, size_t out_sz);
void ela_ws_classify_incoming_frame(uint8_t opcode,
				    const char *payload,
				    size_t payload_len,
				    struct ela_ws_frame_action *out);
int ela_ws_build_zero_mask_control_frame(uint8_t opcode,
					 uint8_t frame[6],
					 size_t *frame_len_out);

#endif
