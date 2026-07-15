// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Remote crash-capture stream for wext-generic fuzzing. Opens a WebSocket to
 * the agent API (from --output-http / ELA_OUTPUT_HTTP[S]) and streams each
 * fuzz payload before it is executed. The API holds only the latest payload;
 * if the host panics and the agent dies, the socket drops ungracefully and the
 * API saves that last payload as a triage artifact. A clean run ends with a
 * "done" frame so the API discards it instead.
 *
 * All calls are best-effort: if no API is configured or the connection fails,
 * open() returns -1 and the caller simply fuzzes without remote capture.
 */
#ifndef WLAN_FUZZ_STREAM_H
#define WLAN_FUZZ_STREAM_H

#include "net/ws_client.h"
#include "wlan_fuzz.h"

struct wlan_fuzz_stream {
	struct ela_ws_conn ws;
	int connected;
	int insecure;
	struct fuzz_payload_sink sink;	/* .ctx points back at this struct */
};

/*
 * Connect to <api>/<endpoint>/<mac> and send the target-name header frame.
 * `endpoint` is the API path segment ("wlan-fuzz"/"eth-fuzz"/"bt-fuzz") so
 * artifacts land in the right place.
 *
 * `stream_payloads`: 1 installs the per-case emit sink (the host-panic
 * dead-man's-switch, streaming every payload before it executes); 0 leaves it
 * off. Either way the sink's crash callback is installed, so a confirmed crash
 * saved locally is also uploaded to the API. `insecure` disables TLS
 * verification (mirrors pcap's --insecure). Returns 0 on success (s->sink is
 * then ready to pass as fuzz_opts.sink), -1 if no API is configured or the
 * connection failed.
 */
int wlan_fuzz_stream_open(struct wlan_fuzz_stream *s, const char *target_name,
			  const char *endpoint, int stream_payloads,
			  int insecure);

/* Graceful end-of-run: tell the API this was a clean finish (no crash to
 * save), then close. No-op if not connected. */
void wlan_fuzz_stream_done(struct wlan_fuzz_stream *s);

#endif
