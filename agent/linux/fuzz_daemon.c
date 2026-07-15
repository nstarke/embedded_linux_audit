// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "fuzz_daemon.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Live daemonization touches fork/setsid/fds; only exercised in the field. */
/* LCOV_EXCL_START */

int ela_fuzz_daemonize(const char *label, const char *out_dir)
{
	char logpath[512];
	pid_t pid;
	int fd, devnull;

	if (!label || !*label)
		label = "fuzz";

	pid = fork();
	if (pid < 0)
		return -1;		/* fall back to foreground */

	if (pid > 0) {
		/* Parent: report the daemon PID and let the caller exit so the
		 * foreground shell (and the API spawn waiting on it) returns. */
		printf("%s: daemonized, pid %d "
		       "(streaming continues in the background)\n",
		       label, (int)pid);
		fflush(stdout);
		return 1;
	}

	/* Child: detach from the controlling terminal and session. */
	setsid();

	/* Keep the fuzz's progress/diagnostics in a log next to the crashes;
	 * fall back to /dev/null if the directory is not writable. */
	if (out_dir && *out_dir) {
		mkdir(out_dir, 0755);
		snprintf(logpath, sizeof(logpath), "%s/%s-daemon.log",
			 out_dir, label);
	} else {
		snprintf(logpath, sizeof(logpath), "/tmp/ela-%s-daemon.log",
			 label);
	}

	devnull = open("/dev/null", O_RDWR);
	fd = open(logpath, O_WRONLY | O_CREAT | O_APPEND, 0600);

	if (devnull >= 0)
		dup2(devnull, STDIN_FILENO);
	if (fd >= 0) {
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
	} else if (devnull >= 0) {
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
	}
	if (devnull > STDERR_FILENO)
		close(devnull);
	if (fd > STDERR_FILENO)
		close(fd);

	return 0;
}

/* LCOV_EXCL_STOP */
