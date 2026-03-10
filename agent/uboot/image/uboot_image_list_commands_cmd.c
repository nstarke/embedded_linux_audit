// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/image/uboot_image_cmd.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --dev <device> --offset <bytes> [--insecure] [--send-logs --output-tcp <IPv4:port>]\n",
		prog);
}

int uboot_image_list_commands_main(int argc, char **argv)
{
	const char *dev = NULL;
	const char *output_tcp = getenv("FW_AUDIT_OUTPUT_TCP");
	const char *output_http = getenv("FW_AUDIT_OUTPUT_HTTP");
	const char *output_https = getenv("FW_AUDIT_OUTPUT_HTTPS");
	uint64_t offset = 0;
	bool have_offset = false;
	bool verbose = getenv("FW_AUDIT_VERBOSE") && !strcmp(getenv("FW_AUDIT_VERBOSE"), "1");
	bool insecure = false;
	bool send_logs = false;
	int opt;
	int rc;

	optind = 1;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "dev", required_argument, NULL, 'd' },
		{ "offset", required_argument, NULL, 'o' },
		{ "output-tcp", required_argument, NULL, 't' },
		{ "output-http", required_argument, NULL, 'O' },
		{ "output-https", required_argument, NULL, 'T' },
		{ "insecure", no_argument, NULL, 'k' },
		{ "send-logs", no_argument, NULL, 'L' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hvd:o:t:O:T:kL", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'v':
			verbose = true;
			break;
		case 'd':
			dev = optarg;
			break;
		case 'o':
			offset = uboot_image_parse_u64(optarg);
			have_offset = true;
			break;
		case 't':
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
		case 'L':
			send_logs = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (!dev || !have_offset) {
		usage(argv[0]);
		return 2;
	}

	if (optind < argc) {
		usage(argv[0]);
		return 2;
	}

	if (!send_logs && output_tcp) {
		fprintf(stderr, "--output-tcp requires --send-logs for list-commands\n");
		return 2;
	}

	rc = uboot_image_prepare(verbose, insecure, send_logs, output_tcp, output_http, output_https);
	if (rc)
		return rc;

	rc = uboot_image_list_commands_execute(dev, offset);
	return uboot_image_finish(rc);
}
