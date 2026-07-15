// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Remote crash-capture stream for cpu fuzzing, the CPU-fuzz counterpart of
 * wlan_fuzz_stream. Opens a WebSocket to the agent API (from --output-http /
 * ELA_OUTPUT_HTTP[S]) and, as a dead-man's-switch, streams each candidate's
 * bytes just before it executes -- so an instruction that wedges or panics the
 * host (killing the agent before local triage runs) still leaves its bytes
 * captured remotely. A confirmed finding file is uploaded whole. All calls are
 * best-effort: with no API configured, open() returns -1 and the caller simply
 * fuzzes without remote capture.
 */
#ifndef CPU_FUZZ_STREAM_H
#define CPU_FUZZ_STREAM_H

#include "net/ws_client.h"
#include "cpu_fuzz.h"

struct cpu_fuzz_stream {
	struct ela_ws_conn ws;
	int connected;
	int insecure;
	struct cpu_fuzz_payload_sink sink;	/* .ctx points back at this */
};

/*
 * Connect to <api>/cpu-fuzz/<mac> and send the target-name header frame.
 * `stream_payloads`: 1 installs the per-candidate emit sink (the host-panic
 * dead-man's-switch); 0 leaves it off but still installs the finding-file
 * upload. `insecure` disables TLS verification. Returns 0 on success (s->sink
 * is then ready to pass as cpu_fuzz_opts.sink), -1 if no API is configured or
 * the connection failed.
 */
int cpu_fuzz_stream_open(struct cpu_fuzz_stream *s, const char *target_name,
			 int stream_payloads, int insecure);

/* Graceful end-of-run: tell the API this was a clean finish, then close. */
void cpu_fuzz_stream_done(struct cpu_fuzz_stream *s);

#endif /* CPU_FUZZ_STREAM_H */
