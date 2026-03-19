// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "linux_download_file_util.h"
#include "util/command_io_util.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <http(s)-url> <output-path>\n"
		"  Download a file from HTTP(S) to a local path\n",
		prog);
}

int linux_download_file_scan_main(int argc, char **argv)
{
	struct ela_download_file_env env = {
		.insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1"),
		.verbose = getenv("ELA_VERBOSE") && !strcmp(getenv("ELA_VERBOSE"), "1"),
	};
	struct ela_download_file_request request;
	struct ela_download_file_result result;
	char errbuf[256];
	char summary[512];
	int ret = 0;

	if (ela_download_file_prepare_request(argc, argv, &env, &request, errbuf, sizeof(errbuf)) != 0) {
		fprintf(stderr, "%s\n", errbuf);
		if (strstr(errbuf, "Unexpected argument:") == NULL &&
		    strstr(errbuf, "non-empty output path") == NULL &&
		    strstr(errbuf, "http:// or https://:") == NULL)
			usage(argv[0]);
		return 2;
	}

	if (request.show_help) {
		usage(argv[0]);
		return 0;
	}

	errbuf[0] = '\0';
	ret = ela_download_file_run(&request, NULL, &result, errbuf, sizeof(errbuf));
	if (ret != 0 && errbuf[0]) {
		fprintf(stderr, "%s\n", errbuf);
	}

	if (ela_download_file_format_summary(summary, sizeof(summary), &result, &request) == 0) {
		fprintf(stderr, "%s", summary);
	}

	return ret;
}
