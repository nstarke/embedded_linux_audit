// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "cpu_fuzz_stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* frame kinds (first byte): target header, case payload, graceful done,
 * confirmed-finding file. Mirrors wlan_fuzz_stream's wire protocol. */
#define FRAME_TARGET 'T'
#define FRAME_CASE   'C'
#define FRAME_DONE   'D'
#define FRAME_CRASH  'X'

#define CPU_STREAM_FRAME_MAX (2 * CPU_INSN_MAX + 160)

/* Live network path; exercised only against a running API in the field. */
/* LCOV_EXCL_START */

static int build_ws_url(const char *http_uri, const char *endpoint,
			const char *mac, char *out, size_t out_sz)
{
	const char *scheme, *authority, *authority_end;
	size_t authority_len;
	int n;

	if (!http_uri || !*http_uri || !endpoint || !*endpoint || !mac ||
	    !*mac || !out || out_sz == 0)
		return -1;
	if (!strncmp(http_uri, "http://", 7)) {
		scheme = "ws://";
		authority = http_uri + 7;
	} else if (!strncmp(http_uri, "https://", 8)) {
		scheme = "wss://";
		authority = http_uri + 8;
	} else {
		return -1;
	}
	authority_end = authority;
	while (*authority_end && *authority_end != '/' &&
	       *authority_end != '?' && *authority_end != '#')
		authority_end++;
	authority_len = (size_t)(authority_end - authority);
	if (!authority_len)
		return -1;
	n = snprintf(out, out_sz, "%s%.*s/%s/%s", scheme,
		     (int)authority_len, authority, endpoint, mac);
	return (n > 0 && (size_t)n < out_sz) ? 0 : -1;
}

static int send_frame(struct cpu_fuzz_stream *s, const char *buf, size_t len)
{
	if (!s->connected)
		return -1;
	if (ela_ws_send_binary(&s->ws, buf, len) != 0) {
		fprintf(stderr,
			"[!] cpu-fuzz stream: send failed; remote capture off\n");
		ela_ws_close(&s->ws);
		s->connected = 0;
		return -1;
	}
	return 0;
}

static void stream_emit(void *ctx, const uint8_t *bytes, int len,
			const char *note)
{
	struct cpu_fuzz_stream *s = ctx;
	char frame[CPU_STREAM_FRAME_MAX];
	static const char hx[] = "0123456789abcdef";
	int i, o;

	if (!s->connected || len < 0)
		return;
	frame[0] = FRAME_CASE;
	frame[1] = ' ';
	o = 2;
	for (i = 0; i < len && i < CPU_INSN_MAX && o + 2 < (int)sizeof(frame); i++) {
		frame[o++] = hx[bytes[i] >> 4];
		frame[o++] = hx[bytes[i] & 0xF];
	}
	if (note && *note && o + 2 < (int)sizeof(frame)) {
		frame[o++] = ' ';
		frame[o++] = '#';
		while (*note && o < (int)sizeof(frame))
			frame[o++] = *note++;
	}
	send_frame(s, frame, (size_t)o);
}

static void stream_crash(void *ctx, const char *findingfile, int len)
{
	struct cpu_fuzz_stream *s = ctx;
	char *frame;

	if (!s->connected || len < 0 || !findingfile)
		return;
	frame = malloc((size_t)len + 2);
	if (!frame)
		return;
	frame[0] = FRAME_CRASH;
	frame[1] = ' ';
	memcpy(frame + 2, findingfile, (size_t)len);
	send_frame(s, frame, (size_t)len + 2);
	free(frame);
}

int cpu_fuzz_stream_open(struct cpu_fuzz_stream *s, const char *target_name,
			 int stream_payloads, int insecure)
{
	const char *https = getenv("ELA_OUTPUT_HTTPS");
	const char *http = getenv("ELA_OUTPUT_HTTP");
	const char *base = (https && *https) ? https : http;
	char mac[64], url[600], hdr[128];
	int n;

	memset(s, 0, sizeof(*s));
	s->ws.sock = -1;
	s->insecure = insecure;
	s->sink.ctx = s;
	s->sink.emit = stream_payloads ? stream_emit : NULL;
	s->sink.crash = stream_crash;

	if (!base || !*base) {
		fprintf(stderr,
			"[!] no --output-http agent API set; remote crash "
			"capture disabled (local triage still active)\n");
		return -1;
	}
	ela_ws_get_primary_mac(mac, sizeof(mac));
	if (build_ws_url(base, "cpu-fuzz", mac, url, sizeof(url)) != 0)
		return -1;
	if (ela_ws_connect_url(url, insecure, &s->ws) != 0) {
		fprintf(stderr, "[!] cpu-fuzz: cannot reach agent API at %s; "
			"remote crash capture disabled\n", url);
		return -1;
	}
	s->connected = 1;

	n = snprintf(hdr, sizeof(hdr), "%c %s", FRAME_TARGET,
		     target_name ? target_name : "cpu-fuzz");
	if (n > 0)
		send_frame(s, hdr, (size_t)n);
	if (s->connected)
		printf("[*] %s to %s for remote crash capture\n",
		       stream_payloads ? "streaming candidates" : "uploading findings",
		       url);
	return s->connected ? 0 : -1;
}

void cpu_fuzz_stream_done(struct cpu_fuzz_stream *s)
{
	char done[2] = { FRAME_DONE, '\0' };

	if (!s->connected)
		return;
	send_frame(s, done, 1);
	if (s->ws.sock >= 0)
		ela_ws_close(&s->ws);
	s->connected = 0;
}

/* LCOV_EXCL_STOP */
