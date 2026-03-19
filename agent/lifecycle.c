// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "lifecycle.h"
#include "embedded_linux_audit_cmd.h"
#include "net/http_client.h"
#include "util/lifecycle_formatter.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int format_utc_timestamp(time_t now, char *buf, size_t buf_size)
{
	struct tm tm_now;

	if (!buf || buf_size == 0)
		return -1;
	if (gmtime_r(&now, &tm_now) == NULL)
		return -1;
	snprintf(buf, buf_size, "%04d-%02d-%02dT%02d:%02d:%02dZ",
		 (int)(tm_now.tm_year + 1900), (int)(tm_now.tm_mon + 1),
		 (int)tm_now.tm_mday, (int)tm_now.tm_hour,
		 (int)tm_now.tm_min, (int)tm_now.tm_sec);
	return 0;
}

static int write_text_lifecycle_event(const char *command,
				      const char *phase,
				      int rc,
				      char *payload_buf,
				      size_t payload_buf_size,
				      size_t *payload_len_out)
{
	char ts_buf[64];
	char rc_buf[32];
	time_t now;
	int payload_len;

	if (!command || !phase || !payload_buf || !payload_len_out || payload_buf_size == 0)
		return -1;

	now = time(NULL);
	if (format_utc_timestamp(now, ts_buf, sizeof(ts_buf)) != 0)
		return -1;
	snprintf(rc_buf, sizeof(rc_buf), "%d", rc);

	payload_len = snprintf(payload_buf,
			       payload_buf_size,
			       "log agent_timestamp=%s phase=%s command=%s rc=%s\n",
			       ts_buf,
			       phase,
			       command,
			       rc_buf);
	if (payload_len < 0 || (size_t)payload_len >= payload_buf_size)
		return -1;

	*payload_len_out = (size_t)payload_len;
	if (write(STDERR_FILENO, payload_buf, *payload_len_out) < 0)
		return -1;
	return 0;
}

bool ela_lifecycle_logging_enabled(void)
{
	const char *ela_debug = getenv("ELA_DEBUG");

	return ela_debug && !strcmp(ela_debug, "1");
}

int ela_emit_lifecycle_event(const char *output_format,
				  const char *output_tcp,
				  const char *output_http,
				  const char *output_https,
				  bool insecure,
				  const char *command,
				  const char *phase,
				  int rc)
{
	char *payload = NULL;
	char text_payload[4096];
	char ts_buf[64];
	struct output_buffer payload_buf = {0};
	const char *fmt = output_format && *output_format ? output_format : "txt";
	const uint8_t *payload_bytes = NULL;
	size_t payload_len = 0;
	const char *output_uri = output_http && *output_http ? output_http : output_https;
	char errbuf[256];

	if (!ela_lifecycle_logging_enabled())
		return 0;

	if (!strcmp(fmt, "txt")) {
		if (write_text_lifecycle_event(command,
					       phase,
					       rc,
					       text_payload,
					       sizeof(text_payload),
					       &payload_len) != 0)
			return -1;
		payload_bytes = (const uint8_t *)text_payload;
	} else {
		if (format_utc_timestamp(time(NULL), ts_buf, sizeof(ts_buf)) != 0)
			return -1;
		if (ela_format_lifecycle_record(&payload_buf, fmt, ts_buf, command, phase, rc) != 0)
			return -1;
		payload = payload_buf.data;
		payload_len = payload_buf.len;
		payload_bytes = (const uint8_t *)payload_buf.data;
	}

	if (output_tcp && *output_tcp) {
		int sock = ela_connect_tcp_ipv4(output_tcp);
		if (sock >= 0) {
			(void)ela_send_all(sock, payload_bytes, payload_len);
			close(sock);
		}
	}

	if (output_uri && *output_uri) {
		char *upload_uri = ela_http_build_upload_uri(output_uri, "log", NULL);
		if (!upload_uri) {
			fprintf(stderr, "Failed to build HTTP(S) log upload URI for %s\n", output_uri);
			} else if (ela_http_post(upload_uri,
						      payload_bytes,
						      payload_len,
						      ela_lifecycle_content_type(output_format),
						      insecure,
						      false,
						      errbuf,
					      sizeof(errbuf)) < 0) {
			fprintf(stderr, "Failed HTTP(S) POST log to %s: %s\n",
				upload_uri,
				errbuf[0] ? errbuf : "unknown error");
		}
		free(upload_uri);
	}

	free(payload);
	return 0;
}
