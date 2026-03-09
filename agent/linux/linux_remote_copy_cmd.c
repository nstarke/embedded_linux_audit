// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <absolute-file-path> [--output-tcp <IPv4:port> | --output-http <http://...> | --output-https <https://...>] [--insecure] [--verbose]\n"
		"  Copy one local file to remote destination\n"
		"  --output-tcp <IPv4:port>       Send file bytes over TCP\n"
		"  --output-http <http://...>     Send file bytes via HTTP POST\n"
		"  --output-https <https://...>   Send file bytes via HTTPS POST\n"
		"  --insecure                     Disable TLS certificate/hostname verification for HTTPS\n"
		"  --verbose                      Print transfer progress\n",
		prog);
}

static int send_file_to_tcp(const char *path, const char *output_tcp, bool verbose)
{
	uint8_t buf[4096];
	int fd;
	int sock;
	uint64_t sent = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}

	sock = uboot_connect_tcp_ipv4(output_tcp);
	if (sock < 0) {
		fprintf(stderr, "Invalid/failed output target (expected IPv4:port): %s\n", output_tcp);
		close(fd);
		return -1;
	}

	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			fprintf(stderr, "Read failure on %s: %s\n", path, strerror(errno));
			close(sock);
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		if (uboot_send_all(sock, buf, (size_t)n) < 0) {
			fprintf(stderr, "Failed sending bytes to %s\n", output_tcp);
			close(sock);
			close(fd);
			return -1;
		}
		sent += (uint64_t)n;
	}

	if (verbose)
		fprintf(stderr, "remote-copy sent %" PRIu64 " bytes from %s to %s\n", sent, path, output_tcp);

	close(sock);
	close(fd);
	return 0;
}

static int send_file_to_http(const char *path, const char *output_uri, bool insecure, bool verbose)
{
	char errbuf[256];
	uint8_t *data = NULL;
	size_t data_len = 0;
	size_t data_cap = 0;
	int fd = -1;
	int rc = -1;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}

	for (;;) {
		uint8_t chunk[4096];
		ssize_t got = read(fd, chunk, sizeof(chunk));
		if (got < 0) {
			fprintf(stderr, "Read failure on %s: %s\n", path, strerror(errno));
			goto out;
		}
		if (got == 0)
			break;

		if (data_len + (size_t)got > data_cap) {
			size_t new_cap = data_cap ? data_cap : 4096;
			uint8_t *tmp;

			while (new_cap < data_len + (size_t)got)
				new_cap *= 2;

			tmp = realloc(data, new_cap);
			if (!tmp) {
				fprintf(stderr, "Unable to grow upload buffer for %s\n", path);
				goto out;
			}
			data = tmp;
			data_cap = new_cap;
		}

		memcpy(data + data_len, chunk, (size_t)got);
		data_len += (size_t)got;
	}

	if (uboot_http_post(output_uri,
			   data,
			   data_len,
			   "application/octet-stream",
			   insecure,
			   verbose,
			   errbuf,
			   sizeof(errbuf)) < 0) {
		fprintf(stderr, "Failed HTTP(S) POST to %s: %s\n", output_uri, errbuf[0] ? errbuf : "unknown error");
		goto out;
	}

	if (verbose)
		fprintf(stderr, "remote-copy sent %" PRIu64 " bytes from %s to %s\n",
			(uint64_t)data_len, path, output_uri);

	rc = 0;

out:
	free(data);
	if (fd >= 0)
		close(fd);
	return rc;
}

int linux_remote_copy_scan_main(int argc, char **argv)
{
	const char *output_tcp = NULL;
	const char *output_http = NULL;
	const char *output_https = NULL;
	const char *output_uri = NULL;
	const char *path = NULL;
	struct stat st;
	bool insecure = false;
	bool verbose = false;
	int opt;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "output-tcp", required_argument, NULL, 'p' },
		{ "output-http", required_argument, NULL, 'O' },
		{ "output-https", required_argument, NULL, 'T' },
		{ "insecure", no_argument, NULL, 'k' },
		{ "verbose", no_argument, NULL, 'v' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hp:O:T:kv", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'p':
			output_tcp = optarg;
			break;
		case 'O':
			output_http = optarg;
			break;
		case 'T':
			output_https = optarg;
			break;
		case 'k':
			insecure = true;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "remote-copy requires an absolute file path\n");
		usage(argv[0]);
		return 2;
	}

	path = argv[optind];
	if (!path || path[0] != '/') {
		fprintf(stderr, "remote-copy requires an absolute file path: %s\n", path ? path : "(null)");
		return 2;
	}

	if (optind + 1 < argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind + 1]);
		usage(argv[0]);
		return 2;
	}

	if (output_http && strncmp(output_http, "http://", 7)) {
		fprintf(stderr, "Invalid --output-http URI (expected http://host:port/...): %s\n", output_http);
		return 2;
	}

	if (output_https && strncmp(output_https, "https://", 8)) {
		fprintf(stderr, "Invalid --output-https URI (expected https://host:port/...): %s\n", output_https);
		return 2;
	}

	if (output_http && output_https) {
		fprintf(stderr, "Use only one of --output-http or --output-https\n");
		return 2;
	}

	if (output_http)
		output_uri = output_http;
	if (output_https)
		output_uri = output_https;

	if ((!output_tcp || !*output_tcp) && (!output_uri || !*output_uri)) {
		fprintf(stderr, "remote-copy requires one of --output-tcp, --output-http, or --output-https\n");
		return 2;
	}

	if (output_tcp && output_uri) {
		fprintf(stderr, "remote-copy accepts only one remote target at a time\n");
		return 2;
	}

	if (stat(path, &st) != 0) {
		fprintf(stderr, "Cannot stat %s: %s\n", path, strerror(errno));
		return 1;
	}

	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "Path is not a regular file: %s\n", path);
		return 1;
	}

	if (output_tcp)
		return send_file_to_tcp(path, output_tcp, verbose) == 0 ? 0 : 1;

	return send_file_to_http(path, output_uri, insecure, verbose) == 0 ? 0 : 1;
}