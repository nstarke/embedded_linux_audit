// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_WS_CLIENT_RUNTIME_UTIL_H
#define ELA_WS_CLIENT_RUNTIME_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ela_ws_runtime_dispatch_ops {
	int (*write_repl_fn)(void *ctx, const char *payload, size_t payload_len);
	int (*send_pong_fn)(void *ctx);
	int (*send_heartbeat_ack_fn)(void *ctx);
};

int ela_ws_format_handshake_error(const char *response,
				  char *errbuf,
				  size_t errbuf_len);
int ela_ws_dispatch_incoming_frame(uint8_t opcode,
				   const char *payload,
				   size_t payload_len,
				   const struct ela_ws_runtime_dispatch_ops *ops,
				   void *ctx);
bool ela_ws_should_reconnect_after_disconnect(int interactive_rc);

#endif /* ELA_WS_CLIENT_RUNTIME_UTIL_H */
