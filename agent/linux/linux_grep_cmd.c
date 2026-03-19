// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "linux_grep_util.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --search <string> --path <absolute-directory> [--recursive]\n"
		"  Search all files in the given absolute directory for the provided string\n"
		"  When --recursive is set, recurse into subdirectories\n"
		"  Output format is always text/plain as: path:line-number:line\n"
		"  When global --output-http is configured, POST matches to /:mac/upload/grep\n",
		prog);
}

int linux_grep_scan_main(int argc, char **argv)
{
	struct ela_grep_env env = {
		.output_tcp = getenv("ELA_OUTPUT_TCP"),
		.output_http = getenv("ELA_OUTPUT_HTTP"),
		.output_https = getenv("ELA_OUTPUT_HTTPS"),
		.insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1"),
	};
	struct ela_grep_request request;
	char errbuf[256];
	int ret;

	ret = ela_grep_prepare_request(argc, argv, &env, NULL, &request, errbuf, sizeof(errbuf));
	if (ret != 0) {
		fprintf(stderr, "%s\n", errbuf);
		if (ret == 2 &&
		    strstr(errbuf, "Use only one of --output-http or --output-https") == NULL &&
		    strstr(errbuf, "Invalid/failed output target") == NULL &&
		    strstr(errbuf, "grep requires a directory path:") == NULL)
			usage(argv[0]);
		return ret;
	}

	if (request.show_help) {
		usage(argv[0]);
		return 0;
	}

	ret = ela_grep_run(&request, NULL, errbuf, sizeof(errbuf));
	if (ret != 0 && errbuf[0])
		fprintf(stderr, "%s\n", errbuf);
	return ret;
}
