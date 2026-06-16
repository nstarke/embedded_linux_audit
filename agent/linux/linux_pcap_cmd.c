// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "linux/linux_pcap_cmd_util.h"
#include "net/ws_client.h"

#include <errno.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Packet capture requires live interfaces and capture privileges, so only
 * argument parsing paths are covered by shell tests.
 */
/* LCOV_EXCL_START */

struct pcap_stream {
	FILE *out;
	struct ela_ws_conn *ws;
	int write_error;
};

static pcap_t *g_capture_handle;

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --interface <ifname> [--stream-to-host]\n"
		"  Capture packets from a Linux network interface as pcap data\n"
		"  Without --stream-to-host, pcap data is written to stdout\n"
		"  With --stream-to-host, global --output-http/--output-https selects the agent API WebSocket\n",
		prog);
}

static void on_capture_signal(int signo)
{
	(void)signo;
	if (g_capture_handle)
		pcap_breakloop(g_capture_handle);
}

static int write_all_fd(int fd, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;

	while (len) {
		ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

static int stream_write(struct pcap_stream *stream, const void *buf, size_t len)
{
	if (stream->write_error)
		return -1;

	if (stream->ws) {
		if (ela_ws_send_binary(stream->ws, buf, len) != 0) {
			stream->write_error = 1;
			return -1;
		}
		return 0;
	}

	if (write_all_fd(fileno(stream->out), buf, len) != 0) {
		stream->write_error = 1;
		return -1;
	}
	return 0;
}

static int write_pcap_global_header(struct pcap_stream *stream, int linktype, int snaplen)
{
	struct ela_pcap_file_header hdr;

	if (ela_pcap_make_global_header(linktype, snaplen, &hdr) != 0)
		return -1;

	return stream_write(stream, &hdr, sizeof(hdr));
}

static void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	struct pcap_stream *stream = (struct pcap_stream *)user;
	struct ela_pcap_record_header rec;

	if (ela_pcap_make_record_header(&h->ts, h->caplen, h->len, &rec) != 0) {
		if (g_capture_handle)
			pcap_breakloop(g_capture_handle);
		return;
	}

	if (stream_write(stream, &rec, sizeof(rec)) != 0 ||
	    stream_write(stream, bytes, h->caplen) != 0) {
		if (g_capture_handle)
			pcap_breakloop(g_capture_handle);
	}
}

static char *build_pcap_ws_url(const char *http_uri)
{
	char mac[18];
	char stack[512];
	char *out;

	ela_ws_get_primary_mac(mac, sizeof(mac));
	if (ela_pcap_build_ws_url(http_uri, mac, stack, sizeof(stack)) != 0)
		return NULL;

	out = strdup(stack);
	if (!out)
		return NULL;
	return out;
}

/*
 * linux_pcap_main orchestrates live packet capture and output streaming.
 *
 * High-level flow:
 *  1) Parse CLI arguments (interface, destination mode, help).
 *  2) Resolve output destination (stdout/file path or host websocket).
 *  3) Open and activate a libpcap capture handle for the selected interface.
 *  4) Emit PCAP global header, then stream per-packet record+payload data.
 *  5) Tear down resources on normal completion, signal interruption, or error.
 *
 * Notes:
 *  - Signal handling uses pcap_breakloop() to terminate the capture loop.
 *  - Error paths are expected to converge on common cleanup before return.
 */
int linux_pcap_main(int argc, char **argv)
{
	/* CLI options accepted by this command. */
	static const struct option long_opts[] = {
		{ "interface",      required_argument, NULL, 'i' },
		{ "stream-to-host", no_argument,       NULL, 's' },
		{ "help",           no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	const char *ifname = NULL;
	const char *output_http;
	const char *output_https;
	const char *output_uri;
	bool stream_to_host = false;
	bool insecure;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *ws_url = NULL;
	struct ela_ws_conn ws;
	struct pcap_stream stream;
	int opt;
	int rc = 1;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hi:s", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 's':
			stream_to_host = true;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "pcap: unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		return 2;
	}
	if (!ifname || !*ifname) {
		fprintf(stderr, "pcap: --interface is required\n");
		usage(argv[0]);
		return 2;
	}

	output_http = getenv("ELA_OUTPUT_HTTP");
	output_https = getenv("ELA_OUTPUT_HTTPS");
	output_uri = (output_https && *output_https) ? output_https : output_http;
	if (output_uri && *output_uri)
		stream_to_host = true;

	memset(&ws, 0, sizeof(ws));
	ws.sock = -1;
	memset(&stream, 0, sizeof(stream));
	stream.out = stdout;

	if (stream_to_host) {
		if (!output_uri || !*output_uri) {
			fprintf(stderr, "pcap: --stream-to-host requires global --output-http or --output-https\n");
			return 2;
		}
		ws_url = build_pcap_ws_url(output_uri);
		if (!ws_url) {
			fprintf(stderr, "pcap: failed to build pcap WebSocket URL from %s\n", output_uri);
			return 2;
		}
		insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
		if (ela_ws_connect_url(ws_url, insecure, &ws) != 0) {
			fprintf(stderr, "pcap: failed to connect to %s\n", ws_url);
			free(ws_url);
			return 1;
		}
		stream.ws = &ws;
	}

	g_capture_handle = pcap_create(ifname, errbuf);
	if (!g_capture_handle) {
		fprintf(stderr, "pcap: failed to create capture on %s: %s\n", ifname, errbuf);
		goto out;
	}
	rc = pcap_set_snaplen(g_capture_handle, 65535);
	(void)rc;
	rc = pcap_set_promisc(g_capture_handle, 1);
	(void)rc;
	rc = pcap_set_timeout(g_capture_handle, 1000);
	(void)rc;
#ifdef PCAP_ERROR_ACTIVATED
	rc = pcap_set_immediate_mode(g_capture_handle, 1);
	(void)rc;
#endif
	if (pcap_activate(g_capture_handle) != 0) {
		fprintf(stderr, "pcap: failed to activate %s: %s\n",
			ifname, pcap_geterr(g_capture_handle));
		goto out;
	}

	if (write_pcap_global_header(&stream,
				     pcap_datalink(g_capture_handle),
				     pcap_snapshot(g_capture_handle)) != 0) {
		fprintf(stderr, "pcap: failed to write pcap header\n");
		goto out;
	}

	signal(SIGINT, on_capture_signal);
	signal(SIGTERM, on_capture_signal);

	rc = pcap_loop(g_capture_handle, -1, handle_packet, (u_char *)&stream);
	if (rc == PCAP_ERROR_BREAK)
		rc = 0;
	else if (rc == PCAP_ERROR) {
		fprintf(stderr, "pcap: capture failed: %s\n", pcap_geterr(g_capture_handle));
		rc = 1;
	}
	if (stream.write_error) {
		fprintf(stderr, "pcap: output stream failed\n");
		rc = 1;
	}

out:
	if (g_capture_handle) {
		pcap_close(g_capture_handle);
		g_capture_handle = NULL;
	}
	if (ws.sock >= 0)
		ela_ws_close(&ws);
	free(ws_url);
	return rc;
}

/* LCOV_EXCL_STOP */
