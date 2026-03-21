// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "linux_execute_command_util.h"

#include "util/command_io_util.h"
#include "util/command_parse_util.h"

#include <stdbool.h>
#include <stdio.h>
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
		"Usage: %s <command-string>\n"
		"  Execute a shell command string and emit/upload its formatted output\n"
		"  Output honors --output-format as txt, csv, or json\n"
		"  When global --output-http is configured, POST output to /:mac/upload/cmd\n",
		prog);
}

int linux_execute_command_scan_main(int argc, char **argv)
{
	struct ela_execute_command_env env = {
		.output_format = getenv("ELA_OUTPUT_FORMAT"),
		.output_tcp = getenv("ELA_OUTPUT_TCP"),
		.output_http = getenv("ELA_OUTPUT_HTTP"),
		.output_https = getenv("ELA_OUTPUT_HTTPS"),
		.insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1"),
	};
	struct ela_execute_command_request request;
	char errbuf[256];

	errbuf[0] = '\0';
	if (ela_execute_command_prepare_request(argc, argv, &env, isatty(STDOUT_FILENO), NULL,
						&request, errbuf, sizeof(errbuf)) != 0) {
		if (errbuf[0]) {
			fprintf(stderr, "%s\n", errbuf);
		}
		usage(argv[0]);
		return 2;
	}

	if (request.show_help) {
		usage(argv[0]);
		return 0;
	}

	if (ela_execute_command_should_run_interactive(&request, isatty(STDOUT_FILENO)))
		return ela_execute_command_run_interactive_with_ops(request.command, NULL);

	errbuf[0] = '\0';
	if (ela_execute_command_run_capture(&request, NULL, errbuf, sizeof(errbuf)) != 0) {
		if (errbuf[0]) {
			fprintf(stderr, "%s\n", errbuf);
		}
		return 1;
	}

	return 0;
}

/* LCOV_EXCL_STOP */
