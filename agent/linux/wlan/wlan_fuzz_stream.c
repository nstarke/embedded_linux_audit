// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "wlan_fuzz_stream.h"
#include "wlan_fuzz_stream_fmt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* frame kinds (first byte): target header, case payload, graceful done */
#define FRAME_TARGET 'T'
#define FRAME_CASE   'C'
#define FRAME_DONE   'D'

/* one CASE frame: 'C' + ' ' + "<msg> <hex> #<note>" for a CASE_MAX_BYTES payload */
#define STREAM_FRAME_MAX (CASE_MAX_BYTES * 2 + 256)

/* Live network path; exercised only against a running API in the field. */
/* LCOV_EXCL_START */

/* Derive ws(s)://<authority>/<endpoint>/<mac> from an http(s) base, mirroring
 * ela_pcap_build_ws_url. */
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

static int send_frame(struct wlan_fuzz_stream *s, const char *buf, size_t len)
{
	if (!s->connected)
		return -1;
	if (ela_ws_send_binary(&s->ws, buf, len) != 0) {
		/* API went away: stop streaming, keep fuzzing locally. */
		fprintf(stderr,
			"[!] nic-fuzz stream: send failed; remote crash capture off\n");
		ela_ws_close(&s->ws);
		s->connected = 0;
		return -1;
	}
	return 0;
}

static void stream_emit(void *ctx, const char *msg_name,
			const uint8_t *payload, int len, const char *note)
{
	struct wlan_fuzz_stream *s = ctx;
	char frame[STREAM_FRAME_MAX];
	int body;

	if (!s->connected)
		return;
	frame[0] = FRAME_CASE;
	frame[1] = ' ';
	body = wlan_fuzz_format_case_line(frame + 2, sizeof(frame) - 2,
					  msg_name, payload, len, note);
	if (body < 0)
		return;
	send_frame(s, frame, (size_t)body + 2);
}

int wlan_fuzz_stream_open(struct wlan_fuzz_stream *s, const char *target_name,
			  const char *endpoint, int insecure)
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
	s->sink.emit = stream_emit;

	if (!endpoint || !*endpoint)
		endpoint = "wlan-fuzz";
	if (!base || !*base) {
		fprintf(stderr,
			"[!] no --output-http agent API set; remote crash "
			"capture disabled (local triage still active)\n");
		return -1;
	}
	ela_ws_get_primary_mac(mac, sizeof(mac));
	if (build_ws_url(base, endpoint, mac, url, sizeof(url)) != 0)
		return -1;
	if (ela_ws_connect_url(url, insecure, &s->ws) != 0) {
		fprintf(stderr, "[!] nic-fuzz: cannot reach agent API at %s; remote "
			"crash capture disabled\n", url);
		return -1;
	}
	s->connected = 1;

	n = snprintf(hdr, sizeof(hdr), "%c %s", FRAME_TARGET,
		     target_name ? target_name : "nic-fuzz");
	if (n > 0)
		send_frame(s, hdr, (size_t)n);
	if (s->connected)
		printf("[*] streaming payloads to %s for remote crash capture\n",
		       url);
	return s->connected ? 0 : -1;
}

void wlan_fuzz_stream_done(struct wlan_fuzz_stream *s)
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
