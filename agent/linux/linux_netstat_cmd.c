// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include "util/output_buffer.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s\n"
		"  List TCP/UDP listening sockets and established connections with PID/program data\n"
		"  Uses 'netstat -tupan' when available, otherwise falls back to 'ss -tupan'\n"
		"  Output format is always text/plain\n"
		"  When global --output-http is configured, POST output to /:mac/upload/netstat\n",
		prog);
}

static int run_netstat_command(struct output_buffer *out)
{
	static const char *cmd =
		"(command -v netstat >/dev/null 2>&1 && exec netstat -tupan) || "
		"(command -v ss >/dev/null 2>&1 && exec ss -tupan)";
	FILE *fp;
	char buf[4096];
	int rc;

	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof(buf), fp)) {
		if (output_buffer_append(out, buf) != 0) {
			(void)pclose(fp);
			errno = ENOMEM;
			return -1;
		}
	}

	rc = pclose(fp);
	if (rc != 0 && out->len == 0)
		return 1;

	return 0;
}

static int emit_remote_outputs(const struct output_buffer *out,
			       const char *output_tcp,
			       const char *output_http,
			       const char *output_https,
			       bool insecure)
{
	const char *output_uri = output_https ? output_https : output_http;
	char errbuf[256];
	int sock;
	char *upload_uri;

	if (output_tcp && *output_tcp) {
		sock = ela_connect_tcp_any(output_tcp);
		if (sock < 0 || ela_send_all(sock, (const uint8_t *)out->data, out->len) != 0) {
			if (sock >= 0)
				close(sock);
			fprintf(stderr, "Failed to send netstat output to %s\n", output_tcp);
			return 1;
		}
		close(sock);
	}

	if (output_uri && *output_uri) {
		upload_uri = ela_http_build_upload_uri(output_uri, "netstat", NULL);
		if (!upload_uri) {
			fprintf(stderr, "Failed to build netstat upload URI\n");
			return 1;
		}
		if (ela_http_post(upload_uri,
				  (const uint8_t *)(out->data ? out->data : ""),
				  out->len,
				  "text/plain; charset=utf-8",
				  insecure,
				  false,
				  errbuf,
				  sizeof(errbuf)) < 0) {
			fprintf(stderr, "Failed to POST netstat output to %s: %s\n",
				upload_uri, errbuf[0] ? errbuf : "unknown error");
			free(upload_uri);
			return 1;
		}
		free(upload_uri);
	}

	return 0;
}

int linux_netstat_scan_main(int argc, char **argv)
{
	struct output_buffer out = {0};
	const char *output_tcp;
	const char *output_http;
	const char *output_https;
	bool insecure;
	int rc;

	if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
			 !strcmp(argv[1], "help"))) {
		usage(argv[0]);
		return 0;
	}
	if (argc > 1) {
		fprintf(stderr, "netstat: unexpected argument: %s\n", argv[1]);
		usage(argv[0]);
		return 2;
	}

	rc = run_netstat_command(&out);
	if (rc != 0) {
		if (rc < 0)
			fprintf(stderr, "netstat: failed to collect socket table: %s\n", strerror(errno));
		else
			fprintf(stderr, "netstat: neither netstat nor ss is available\n");
		free(out.data);
		return 1;
	}

	if (out.len > 0 && fwrite(out.data, 1, out.len, stdout) != out.len) {
		fprintf(stderr, "netstat: failed to write output\n");
		free(out.data);
		return 1;
	}

	output_tcp = getenv("ELA_OUTPUT_TCP");
	output_http = getenv("ELA_OUTPUT_HTTP");
	output_https = getenv("ELA_OUTPUT_HTTPS");
	insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	rc = emit_remote_outputs(&out, output_tcp, output_http, output_https, insecure);

	free(out.data);
	return rc;
}

/* LCOV_EXCL_STOP */
