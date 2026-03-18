// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../embedded_linux_audit_cmd.h"
#include "../net/ws_client.h"
#include "../shell/interactive.h"
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
	int sock;
	int fd;
	char buf[65536];
	ssize_t n;
	pid_t pid;
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

	if (ela_is_ws_url(options.target)) {
		struct ela_ws_conn ws;

		if (ela_ws_connect(options.target, options.insecure, &ws) != 0) {
			fprintf(stderr, "transfer: failed to connect to %s\n", options.target);
			return 1;
		}

		pid = fork();
		if (pid < 0) {
			ela_ws_close_parent_fd(&ws);
			fprintf(stderr, "transfer: fork failed: %s\n", strerror(errno));
			return 1;
		}

		if (pid > 0) {
			/* Parent: release socket fd without disrupting the child's session */
			ela_ws_close_parent_fd(&ws);
			fprintf(stdout, "Transfer started (pid=%ld)\n", (long)pid);
			return 0;
		}

		/* Daemon child */
		setsid();
		{
			int reconnect = 1;
			int failed_attempts = 0;
			for (;;) {
				if (ela_ws_run_interactive(&ws, argv[0]) == ELA_WS_EXIT_CLEAN) {
					ela_ws_close(&ws);
					exit(0);
				}
				ela_ws_close(&ws);

				if (options.retry_attempts == 0)
					break;

				reconnect = 0;
				for (;;) {
					failed_attempts++;
					if (failed_attempts > options.retry_attempts)
						break;
					fprintf(stderr,
						"transfer: reconnect attempt %d/%d, waiting %ds\n",
						failed_attempts, options.retry_attempts,
						TRANSFER_RETRY_DELAY_SECS);
					sleep(TRANSFER_RETRY_DELAY_SECS);
					if (ela_ws_connect(options.target, options.insecure, &ws) == 0) {
						failed_attempts = 0;
						reconnect = 1;
						break;
					}
					fprintf(stderr, "transfer: failed to connect to %s\n", options.target);
				}
				if (!reconnect)
					break;
			}
			fprintf(stderr,
				"transfer: max retry attempts (%d) reached, exiting\n",
				options.retry_attempts);
			exit(1);
		}
	}

	fd = open("/proc/self/exe", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "transfer: failed to open binary: %s\n", strerror(errno));
		return 1;
	}

	sock = ela_connect_tcp_any(options.target);
	if (sock < 0) {
		fprintf(stderr, "transfer: failed to connect to %s\n", options.target);
		close(fd);
		return 1;
	}

	/* Daemonize: parent reports and exits, child handles transfer + interactive session */
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "transfer: fork failed: %s\n", strerror(errno));
		close(fd);
		close(sock);
		return 1;
	}

	if (pid > 0) {
		/* Parent */
		close(fd);
		close(sock);
		fprintf(stdout, "Transfer started (pid=%ld)\n", (long)pid);
		return 0;
	}

	/* Daemon child */
	setsid();

	/* Send the binary over the socket */
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		if (ela_send_all(sock, (const uint8_t *)buf, (size_t)n) < 0) {
			close(fd);
			close(sock);
			exit(1);
		}
	}
	close(fd);

	if (n < 0) {
		close(sock);
		exit(1);
	}

	/* Switch stdin/stdout/stderr to the socket and serve an interactive session */
	dup2(sock, STDIN_FILENO);
	dup2(sock, STDOUT_FILENO);
	dup2(sock, STDERR_FILENO);
	close(sock);

	exit(interactive_loop(argv[0]));
}
