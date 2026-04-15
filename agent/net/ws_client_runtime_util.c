// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ws_client_runtime_util.h"

#include "ws_client.h"
#include "ws_session_util.h"

#include <stdio.h>

int ela_ws_format_handshake_error(const char *response,
				  char *errbuf,
				  size_t errbuf_len)
{
	char detail[128];

	if (ela_ws_validate_handshake_response(response, detail, sizeof(detail)) == 0) {
		if (errbuf && errbuf_len)
			errbuf[0] = '\0';
		return 0;
	}

	if (errbuf && errbuf_len) {
		if (ela_ws_handshake_response_is_unauthorized(response)) {
			snprintf(errbuf, errbuf_len,
				 "ws: server returned 401 Unauthorized\n"
				 "  Set a bearer token via --api-key, ELA_API_KEY, or /tmp/ela.key");
		} else if (detail[0]) {
			snprintf(errbuf, errbuf_len, "ws: %s", detail);
		} else {
			snprintf(errbuf, errbuf_len, "ws: handshake failed");
		}
	}

	return -1;
}

int ela_ws_dispatch_incoming_frame(uint8_t opcode,
				   const char *payload,
				   size_t payload_len,
				   const struct ela_ws_runtime_dispatch_ops *ops,
				   void *ctx)
{
	struct ela_ws_frame_action action;

	if (!ops)
		return -1;

	ela_ws_classify_incoming_frame(opcode, payload, payload_len, &action);
	if (action.terminate_session)
		return 1;
	if (action.send_pong)
		return ops->send_pong_fn ? ops->send_pong_fn(ctx) : -1;
	if (action.send_heartbeat_ack)
		return ops->send_heartbeat_ack_fn ? ops->send_heartbeat_ack_fn(ctx) : -1;
	if (action.forward_to_repl)
		return ops->write_repl_fn ? ops->write_repl_fn(ctx, payload, payload_len) : -1;
	return 0;
}

bool ela_ws_should_reconnect_after_disconnect(int interactive_rc)
{
	return interactive_rc != ELA_WS_EXIT_CLEAN;
}

bool ela_ws_reconnect_budget_exhausted(int failed_attempts, int max_attempts)
{
	return failed_attempts > max_attempts;
}
