// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "linux/linux_coredump_util.h"
#include "net/api_key.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * This command writes host kernel coredump settings and is covered through the
 * injectable utility layer in unit tests.
 */
/* LCOV_EXCL_START */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--output-dir /tmp] [--config-path /tmp/ela-coredump.conf]\n"
		"       %s off [--config-path /tmp/ela-coredump.conf]\n"
		"  Configure Linux to write process coredumps to /tmp.\n"
		"  With global --output-http, future coredumps are also POSTed to /:mac/upload/coredump.\n",
		prog, prog);
}

static int run_collect(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "output-dir",  required_argument, NULL, 'o' },
		{ "config-path", required_argument, NULL, 'c' },
		{ "pid",         required_argument, NULL, 'p' },
		{ "signal",      required_argument, NULL, 's' },
		{ "time",        required_argument, NULL, 't' },
		{ "exe",         required_argument, NULL, 'e' },
		{ "help",        no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	struct ela_coredump_collect_request request = {
		.output_dir = ELA_COREDUMP_DEFAULT_OUTPUT_DIR,
		.config_path = ELA_COREDUMP_DEFAULT_CONFIG_PATH,
	};
	char errbuf[256];
	char out_path[512];
	int opt;

	optind = 2;
	while ((opt = getopt_long(argc, argv, "ho:c:p:s:t:e:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'o':
			request.output_dir = optarg;
			break;
		case 'c':
			request.config_path = optarg;
			break;
		case 'p':
			request.pid = optarg;
			break;
		case 's':
			request.signal = optarg;
			break;
		case 't':
			request.timestamp = optarg;
			break;
		case 'e':
			request.exe_name = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	request.insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	errbuf[0] = '\0';
	if (ela_coredump_collect(&request, NULL, out_path, sizeof(out_path),
				 errbuf, sizeof(errbuf)) != 0) {
		fprintf(stderr, "%s\n", errbuf[0] ? errbuf : "coredump: collect failed");
		return 1;
	}
	return 0;
}

static int run_off(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "config-path", required_argument, NULL, 'c' },
		{ "help",        no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	const char *config_path = ELA_COREDUMP_DEFAULT_CONFIG_PATH;
	char errbuf[256];
	int opt;

	optind = 2;
	while ((opt = getopt_long(argc, argv, "hc:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			config_path = optarg;
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
		fprintf(stderr, "coredump off: unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		return 2;
	}

	errbuf[0] = '\0';
	if (ela_coredump_disable(config_path, NULL, errbuf, sizeof(errbuf)) != 0) {
		fprintf(stderr, "%s\n", errbuf[0] ? errbuf : "coredump: disable failed");
		return 1;
	}
	printf("coredumps disabled\n");
	return 0;
}

int linux_coredump_main(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "output-dir",  required_argument, NULL, 'o' },
		{ "config-path", required_argument, NULL, 'c' },
		{ "help",        no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	struct ela_coredump_config_request request = {
		.output_dir = ELA_COREDUMP_DEFAULT_OUTPUT_DIR,
		.config_path = ELA_COREDUMP_DEFAULT_CONFIG_PATH,
	};
	char exe_path[512];
	char errbuf[256];
	ssize_t got;
	int opt;

	if (argc > 1 && !strcmp(argv[1], "collect"))
		return run_collect(argc, argv);
	if (argc > 1 && !strcmp(argv[1], "off"))
		return run_off(argc, argv);

	got = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (got < 0 || got >= (ssize_t)sizeof(exe_path)) {
		fprintf(stderr, "coredump: failed to resolve current executable path\n");
		return 1;
	}
	exe_path[got] = '\0';
	request.collector_path = exe_path;
	request.output_uri = getenv("ELA_OUTPUT_HTTPS");
	if (!request.output_uri || !*request.output_uri)
		request.output_uri = getenv("ELA_OUTPUT_HTTP");
	request.api_key = ela_api_key_get();
	request.insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");

	optind = 1;
	while ((opt = getopt_long(argc, argv, "ho:c:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'o':
			request.output_dir = optarg;
			break;
		case 'c':
			request.config_path = optarg;
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
		fprintf(stderr, "coredump: unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		return 2;
	}

	errbuf[0] = '\0';
	if (ela_coredump_configure(&request, NULL, errbuf, sizeof(errbuf)) != 0) {
		fprintf(stderr, "%s\n", errbuf[0] ? errbuf : "coredump: configuration failed");
		return 1;
	}
	printf("coredumps enabled: %s\n", request.output_dir);
	if (request.output_uri && *request.output_uri)
		printf("coredump uploads enabled: %s\n", request.output_uri);
	return 0;
}

/* LCOV_EXCL_STOP */
