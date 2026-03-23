// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef WS_CLIENT_H
#define WS_CLIENT_H

#include "api_key.h"

/*
 * Native WebSocket connection handle.  No curl types here; TLS state is held
 * as void* so callers don't need to pull in wolfSSL or OpenSSL headers.
 */
struct ela_ws_conn {
	int   sock;                           /* raw TCP socket fd */
	int   is_tls;                         /* 1 for wss://, 0 for ws:// */
	void *ssl;                            /* WOLFSSL* or SSL* (wss:// only) */
	void *ssl_ctx;                        /* WOLFSSL_CTX* or SSL_CTX* */
	char  auth_token[ELA_API_KEY_MAX_LEN + 4]; /* copy of bearer token */
};

/*
 * Connect to a WebSocket server.  Discovers the primary MAC address and
 * appends "/terminal/<mac>" to the base URL.  insecure=1 disables TLS
 * peer/host verification.  Returns 0 on success, -1 on error.
 */
int ela_ws_connect(const char *base_url, int insecure,
		   struct ela_ws_conn *ws_out);

/*
 * Connect to a WebSocket server using exactly the given URL (no path
 * rewriting or MAC suffix).  insecure=1 disables TLS verification.
 * Returns 0 on success, -1 on error.
 */
int ela_ws_connect_url(const char *url, int insecure,
		       struct ela_ws_conn *ws_out);

/*
 * Bidirectional binary proxy between a WebSocket connection and a raw fd
 * (e.g. one end of a socketpair carrying GDB RSP bytes).
 * Received binary WS frames are written to rsp_fd; bytes read from rsp_fd
 * are sent as binary WS frames.  Returns when either side closes/errors.
 *
 * debug_fd: if >= 0 and ELA_DEBUG=1, per-frame log lines are written here
 * (pass g_gdb_debug_fd from linux_gdbserver_cmd.c, or -1 to disable).
 */
int ela_ws_run_gdb_bridge(struct ela_ws_conn *ws, int rsp_fd, int debug_fd);

/*
 * Close the parent's copy of the socket after fork() without sending a
 * WebSocket CLOSE frame, which would disrupt the child's session.
 */
void ela_ws_close_parent_fd(const struct ela_ws_conn *ws);

/*
 * Fully close a WebSocket connection: free TLS state and close the socket.
 * Safe to call on a zero-initialised struct.
 */
void ela_ws_close(struct ela_ws_conn *ws);

/*
 * Run an interactive REPL session over the established WebSocket connection.
 * interactive_loop() runs in a forked child process bridged via pipes.
 * Received text frames containing "_type":"heartbeat" are answered with the
 * current date and not forwarded to the REPL.
 * Returns 0 on connection drop/error (caller may reconnect),
 *         ELA_WS_EXIT_CLEAN if the child process exited normally (no reconnect).
 */
#define ELA_WS_EXIT_CLEAN 2
int ela_ws_run_interactive(struct ela_ws_conn *ws, const char *prog);

#endif /* WS_CLIENT_H */
