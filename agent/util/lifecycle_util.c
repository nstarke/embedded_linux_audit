// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "lifecycle_util.h"
#include "lifecycle_formatter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef ELA_AGENT_UNIT_TESTS

static time_t  default_time(time_t *t)                                   { return time(t); }
static ssize_t default_write(int fd, const void *buf, size_t len)        { (void)fd; (void)buf; return (ssize_t)len; }
static int     default_connect_tcp(const char *spec)                      { (void)spec; return -1; }
static int     default_send_all(int sock, const uint8_t *b, size_t l)    { (void)sock; (void)b; (void)l; return -1; }
static int     default_close(int fd)                                      { (void)fd; return 0; }
static char   *default_build_upload_uri(const char *b, const char *t, const char *p) { (void)b; (void)t; (void)p; return NULL; }
static int     default_http_post(const char *u, const uint8_t *d, size_t l,
				 const char *ct, bool i, bool v,
				 char *e, size_t el)
{
	(void)u; (void)d; (void)l; (void)ct; (void)i; (void)v; (void)e; (void)el;
	return -1;
}

#else

#include "../embedded_linux_audit_cmd.h"

static time_t  default_time(time_t *t)                                   { return time(t); }
static ssize_t default_write(int fd, const void *buf, size_t len)        { return write(fd, buf, len); }
static int     default_connect_tcp(const char *spec)                      { return ela_connect_tcp_ipv4(spec); }
static int     default_send_all(int sock, const uint8_t *b, size_t l)    { return ela_send_all(sock, b, l); }
static int     default_close(int fd)                                      { return close(fd); }
static char   *default_build_upload_uri(const char *b, const char *t, const char *p) { return ela_http_build_upload_uri(b, t, p); }
static int     default_http_post(const char *u, const uint8_t *d, size_t l,
				 const char *ct, bool i, bool v,
				 char *e, size_t el)
{
	return ela_http_post(u, d, l, ct, i, v, e, el);
}

#endif /* ELA_AGENT_UNIT_TESTS */

static const struct ela_lifecycle_io_ops default_ops = {
	.time_fn             = default_time,
	.write_fn            = default_write,
	.connect_tcp_fn      = default_connect_tcp,
	.send_all_fn         = default_send_all,
	.close_fn            = default_close,
	.build_upload_uri_fn = default_build_upload_uri,
	.http_post_fn        = default_http_post,
};

int ela_emit_lifecycle_event_ex(const struct ela_lifecycle_io_ops *ops,
				const char *output_format,
				const char *output_tcp,
				const char *output_http,
				const char *output_https,
				bool insecure,
				const char *command,
				const char *phase,
				int rc)
{
	const struct ela_lifecycle_io_ops *eff = ops ? ops : &default_ops;
	const char *fmt = (output_format && *output_format) ? output_format : "txt";
	const char *output_uri = (output_http && *output_http) ? output_http : output_https;
	struct output_buffer payload_buf = {0};
	char ts_buf[64];
	char errbuf[256];
	time_t now;

	if (!command || !phase)
		return -1;

	now = eff->time_fn(NULL);
	if (ela_format_utc_timestamp(now, ts_buf, sizeof(ts_buf)) != 0)
		return -1;

	if (ela_format_lifecycle_record(&payload_buf, fmt, ts_buf, command, phase, rc) != 0)
		return -1;

	/* txt format also echoes to stderr */
	if (!strcmp(fmt, "txt"))
		(void)eff->write_fn(STDERR_FILENO, payload_buf.data, payload_buf.len);

	if (output_tcp && *output_tcp) {
		int sock = eff->connect_tcp_fn(output_tcp);

		if (sock >= 0) {
			(void)eff->send_all_fn(sock, (const uint8_t *)payload_buf.data, payload_buf.len);
			eff->close_fn(sock);
		}
	}

	if (output_uri && *output_uri) {
		char *upload_uri = eff->build_upload_uri_fn(output_uri, "log", NULL);

		if (!upload_uri) {
			fprintf(stderr, "Failed to build HTTP(S) log upload URI for %s\n", output_uri);
		} else {
			errbuf[0] = '\0';
			if (eff->http_post_fn(upload_uri,
					      (const uint8_t *)payload_buf.data,
					      payload_buf.len,
					      ela_lifecycle_content_type(output_format),
					      insecure, false,
					      errbuf, sizeof(errbuf)) < 0) {
				fprintf(stderr, "Failed HTTP(S) POST log to %s: %s\n",
					upload_uri,
					errbuf[0] ? errbuf : "unknown error");
			}
			free(upload_uri);
		}
	}

	free(payload_buf.data);
	return 0;
}
