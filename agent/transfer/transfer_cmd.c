// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../embedded_linux_audit_cmd.h"
#include "transfer_cmd_util.h"
#include "../util/transfer_parse_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define TRANSFER_DEFAULT_RETRY_ATTEMPTS 5
#define TRANSFER_RETRY_DELAY_SECS       60

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--insecure] [--retry-attempts <n>] <host:port|ws://...|wss://...>\n"
		"  Transfer (send) this binary to a receiver listening at host:port,\n"
		"  then daemonize and serve an interactive session over the same connection.\n"
		"  For ws:// or wss:// targets, an interactive session is established over\n"
		"  WebSocket without transferring the binary.\n"
		"  --insecure          Disable TLS certificate verification (for self-signed certs)\n"
		"  --retry-attempts <n>  Reconnect up to n times on disconnect (default: %d, 0=no retry)\n"
		"                        Each retry waits %d seconds before attempting.\n"
		"  The receiver for raw TCP may be started with:\n"
		"    nc -l <port> > embedded_linux_audit && chmod +x embedded_linux_audit\n",
		prog, TRANSFER_DEFAULT_RETRY_ATTEMPTS, TRANSFER_RETRY_DELAY_SECS);
}

int transfer_main(int argc, char **argv)
{
	struct ela_transfer_options options;
	struct ela_transfer_request request;
	struct ela_transfer_result result;
	char errbuf[256];

	if (ela_transfer_parse_args(argc, argv, getenv("ELA_WS_RETRY_ATTEMPTS"),
				    TRANSFER_DEFAULT_RETRY_ATTEMPTS,
				    &options, errbuf, sizeof(errbuf)) != 0) {
		if (errbuf[0])
			fprintf(stderr, "transfer: %s\n", errbuf);
		usage(argv[0]);
		return 2;
	}

	if (options.show_help) {
		usage(argv[0]);
		return 0;
	}

	memset(&request, 0, sizeof(request));
	request.prog = argv[0];
	request.self_exe_path = "/proc/self/exe";
	request.options = options;

	errbuf[0] = '\0';
	if (ela_transfer_execute(&request, NULL, NULL, &result, errbuf, sizeof(errbuf)) != 0) {
		if (errbuf[0])
			fprintf(stderr, "%s\n", errbuf);
		return result.exit_code ? result.exit_code : 1;
	}

	if (!result.started)
		return result.exit_code;
	return 0;
}
