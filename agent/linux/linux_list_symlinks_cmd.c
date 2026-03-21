// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "linux_list_symlinks_util.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [absolute-directory] [--recursive]\n"
		"  List symlinks under the given absolute directory (default: /)\n"
		"  When --recursive is set, recurse into subdirectories\n"
		"  Output honors --output-format as txt, csv, or json\n"
		"  When global --output-http is configured, POST the list to /:mac/upload/symlink-list\n",
		prog);
}

int linux_list_symlinks_scan_main(int argc, char **argv)
{
	struct ela_list_symlinks_env env = {
		.output_format = getenv("ELA_OUTPUT_FORMAT"),
		.output_tcp = getenv("ELA_OUTPUT_TCP"),
		.output_http = getenv("ELA_OUTPUT_HTTP"),
		.output_https = getenv("ELA_OUTPUT_HTTPS"),
		.insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1"),
	};
	struct ela_list_symlinks_request request;
	char errbuf[256];
	int ret;

	ret = ela_list_symlinks_prepare_request(argc, argv, &env, NULL, &request, errbuf, sizeof(errbuf));
	if (ret != 0) {
		fprintf(stderr, "%s\n", errbuf);
		if (ret == 2 &&
		    strstr(errbuf, "Use only one of --output-http or --output-https") == NULL &&
		    strstr(errbuf, "Invalid/failed output target") == NULL &&
		    strstr(errbuf, "list-symlinks requires a directory path:") == NULL &&
		    strstr(errbuf, "Invalid output format for list-symlinks:") == NULL)
			usage(argv[0]);
		return ret;
	}

	if (request.show_help) {
		usage(argv[0]);
		return 0;
	}

	ret = ela_list_symlinks_run(&request, NULL, errbuf, sizeof(errbuf));
	if (ret != 0 && errbuf[0])
		fprintf(stderr, "%s\n", errbuf);
	return ret;
}

/* LCOV_EXCL_STOP */
