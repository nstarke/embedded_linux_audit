// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../embedded_linux_audit_cmd.h"
#include "linux_process_watch_util.h"
#include "../net/http_client.h"
#include "../net/tcp_util.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_WATCH_ENTRIES 64

/* =========================================================================
 * Daemon state
 * ====================================================================== */

static volatile sig_atomic_t g_stop = 0;
static int g_watch_sock  = -1;
static const char *g_watch_http_uri = NULL;
static bool g_watch_insecure = false;

static void watch_signal_handler(int sig)
{
	(void)sig;
	g_stop = 1;
}

/* =========================================================================
 * Exclusive lock helpers
 * ====================================================================== */

static int lock_acquire(void)
{
	int fd = open(ELA_PROCESS_WATCH_LOCK_FILE, O_CREAT | O_RDWR, 0600);

	if (fd < 0)
		return -1;
	if (flock(fd, LOCK_EX) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void lock_release(int fd)
{
	if (fd >= 0) {
		flock(fd, LOCK_UN);
		close(fd);
	}
}

/* =========================================================================
 * State file I/O (must be called with lock held)
 * ====================================================================== */

static int state_read(char needles[][ELA_PROCESS_WATCH_NEEDLE_MAX + 1],
		      char pids[][ELA_PROCESS_WATCH_PIDS_MAX_LEN],
		      int *count, int max)
{
	FILE *fp;
	char line[ELA_PROCESS_WATCH_NEEDLE_MAX + ELA_PROCESS_WATCH_PIDS_MAX_LEN + 4];
	char needle[ELA_PROCESS_WATCH_NEEDLE_MAX + 1];
	char pids_buf[ELA_PROCESS_WATCH_PIDS_MAX_LEN];

	*count = 0;
	fp = fopen(ELA_PROCESS_WATCH_STATE_FILE, "r");
	if (!fp)
		return 0; /* no state file = no watches */

	while (fgets(line, sizeof(line), fp) && *count < max) {
		if (ela_process_watch_state_parse_line(line,
						       needle, sizeof(needle),
						       pids_buf, sizeof(pids_buf)) != 0)
			continue;
		snprintf(needles[*count], ELA_PROCESS_WATCH_NEEDLE_MAX + 1,
			 "%s", needle);
		snprintf(pids[*count], ELA_PROCESS_WATCH_PIDS_MAX_LEN,
			 "%s", pids_buf);
		(*count)++;
	}
	fclose(fp);
	return 0;
}

static int state_write(char needles[][ELA_PROCESS_WATCH_NEEDLE_MAX + 1],
		       char pids[][ELA_PROCESS_WATCH_PIDS_MAX_LEN],
		       int count)
{
	char tmp_path[] = ELA_PROCESS_WATCH_STATE_FILE ".tmp";
	FILE *fp;
	char line[ELA_PROCESS_WATCH_NEEDLE_MAX + ELA_PROCESS_WATCH_PIDS_MAX_LEN + 4];
	int i;

	fp = fopen(tmp_path, "w");
	if (!fp)
		return -1;

	for (i = 0; i < count; i++) {
		if (ela_process_watch_state_format_line(needles[i], pids[i],
							line, sizeof(line)) != 0)
			continue;
		fputs(line, fp);
	}
	fclose(fp);
	return rename(tmp_path, ELA_PROCESS_WATCH_STATE_FILE);
}

/* =========================================================================
 * PID file helpers
 * ====================================================================== */

static int write_pid_file(pid_t pid)
{
	FILE *fp = fopen(ELA_PROCESS_WATCH_PID_FILE, "w");

	if (!fp)
		return -1;
	fprintf(fp, "%ld\n", (long)pid);
	fclose(fp);
	return 0;
}

static pid_t read_pid_file(void)
{
	FILE *fp;
	long pid = -1;

	fp = fopen(ELA_PROCESS_WATCH_PID_FILE, "r");
	if (!fp)
		return -1;
	if (fscanf(fp, "%ld", &pid) != 1)
		pid = -1;
	fclose(fp);
	return (pid > 0) ? (pid_t)pid : -1;
}

/* =========================================================================
 * /proc scanning
 * ====================================================================== */

/*
 * Collect PIDs of all processes whose cmdline contains needle.
 * Fills pids_out with a sorted, comma-separated list (e.g. "123,456,789").
 * Returns 0 on success, -1 on failure.
 */
static int scan_pids_for_needle(const char *needle,
				char *pids_out, size_t pids_sz)
{
	DIR *dp;
	struct dirent *ent;
	pid_t found[1024];
	int count = 0;
	char path[64];
	char cmdline[4096];
	FILE *fp;
	size_t n;
	int i;

	pids_out[0] = '\0';

	dp = opendir("/proc");
	if (!dp)
		return -1;

	while ((ent = readdir(dp)) != NULL && count < (int)(sizeof(found) / sizeof(found[0]))) {
		if (!isdigit((unsigned char)ent->d_name[0]))
			continue;
		pid_t pid = (pid_t)atoi(ent->d_name);
		if (pid <= 0)
			continue;

		snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
		fp = fopen(path, "r");
		if (!fp)
			continue;

		n = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
		fclose(fp);

		if (n == 0)
			continue;
		cmdline[n] = '\0';

		/* cmdline uses NUL bytes to separate argv; replace with spaces */
		for (size_t j = 0; j < n; j++)
			if (cmdline[j] == '\0')
				cmdline[j] = ' ';

		if (strstr(cmdline, needle))
			found[count++] = pid;
	}
	closedir(dp);

	/* Sort ascending so the string representation is deterministic */
	for (i = 0; i < count - 1; i++) {
		int j;
		for (j = i + 1; j < count; j++) {
			if (found[j] < found[i]) {
				pid_t tmp = found[i];
				found[i]  = found[j];
				found[j]  = tmp;
			}
		}
	}

	/* Build comma-separated string */
	{
		size_t pos = 0;
		char tmp[32];
		int w;

		for (i = 0; i < count; i++) {
			w = snprintf(tmp, sizeof(tmp), "%ld", (long)found[i]);
			if (w <= 0)
				continue;
			if (pos + (i > 0 ? 1U : 0U) + (size_t)w + 1U > pids_sz)
				break;
			if (i > 0)
				pids_out[pos++] = ',';
			memcpy(pids_out + pos, tmp, (size_t)w);
			pos += (size_t)w;
			pids_out[pos] = '\0';
		}
	}
	return 0;
}

/* =========================================================================
 * Output helpers (daemon-side)
 * ====================================================================== */

static const char *event_content_type(const char *fmt)
{
	if (!strcmp(fmt, "json"))
		return "application/json; charset=utf-8";
	if (!strcmp(fmt, "csv"))
		return "text/csv; charset=utf-8";
	return "text/plain; charset=utf-8";
}

static void emit_event(const char *needle,
		       const char *old_pids, const char *new_pids,
		       const char *fmt)
{
	char *buf = NULL;
	size_t len = 0;
	char errbuf[256];

	if (ela_process_watch_format_event(needle, old_pids, new_pids,
					   fmt, &buf, &len) != 0 || !buf)
		return;

	if (g_watch_sock < 0 && !g_watch_http_uri)
		fwrite(buf, 1, len, stdout);

	if (g_watch_sock >= 0)
		(void)ela_send_all(g_watch_sock, (const uint8_t *)buf, len);

	if (g_watch_http_uri) {
		char *uri = ela_http_build_upload_uri(g_watch_http_uri,
						      "process_watch", NULL);
		if (uri) {
			(void)ela_http_post(uri, (const uint8_t *)buf, len,
					    event_content_type(fmt),
					    g_watch_insecure, false,
					    errbuf, sizeof(errbuf));
			free(uri);
		}
	}

	free(buf);
}

/* =========================================================================
 * Daemon poll loop
 * ====================================================================== */

static void poll_loop(const char *fmt)
{
	char needles[MAX_WATCH_ENTRIES][ELA_PROCESS_WATCH_NEEDLE_MAX + 1];
	char known_pids[MAX_WATCH_ENTRIES][ELA_PROCESS_WATCH_PIDS_MAX_LEN];
	char current_pids[ELA_PROCESS_WATCH_PIDS_MAX_LEN];
	int count = 0;
	int lock_fd;
	int i;
	int s;

	/* Prime the in-memory state */
	lock_fd = lock_acquire();
	state_read(needles, known_pids, &count, MAX_WATCH_ENTRIES);
	lock_release(lock_fd);

	while (!g_stop) {
		lock_fd = lock_acquire();
		if (lock_fd < 0) {
			for (s = 0; s < ELA_PROCESS_WATCH_POLL_SECS && !g_stop; s++)
				sleep(1);
			continue;
		}

		/* Re-read to pick up needles added/removed by watch on/off */
		{
			char new_needles[MAX_WATCH_ENTRIES][ELA_PROCESS_WATCH_NEEDLE_MAX + 1];
			char new_pids[MAX_WATCH_ENTRIES][ELA_PROCESS_WATCH_PIDS_MAX_LEN];
			int new_count = 0;
			int j;

			state_read(new_needles, new_pids, &new_count, MAX_WATCH_ENTRIES);

			/* Merge: carry forward known PIDs for needles we already track */
			for (j = 0; j < new_count; j++) {
				new_pids[j][0] = '\0'; /* start empty */
				for (i = 0; i < count; i++) {
					if (!strcmp(needles[i], new_needles[j])) {
						snprintf(new_pids[j], ELA_PROCESS_WATCH_PIDS_MAX_LEN,
							"%s", known_pids[i]);
						break;
					}
				}
			}

			memcpy(needles, new_needles, sizeof(needles));
			memcpy(known_pids, new_pids, sizeof(known_pids));
			count = new_count;
		}

		/* Scan and detect changes */
		for (i = 0; i < count && !g_stop; i++) {
			if (scan_pids_for_needle(needles[i],
						 current_pids,
						 sizeof(current_pids)) != 0)
				continue;

			if (!ela_process_watch_pids_equal(known_pids[i], current_pids)) {
				emit_event(needles[i], known_pids[i], current_pids, fmt);
				snprintf(known_pids[i], ELA_PROCESS_WATCH_PIDS_MAX_LEN,
					 "%s", current_pids);
			}
		}

		state_write(needles, known_pids, count);
		lock_release(lock_fd);

		for (s = 0; s < ELA_PROCESS_WATCH_POLL_SECS && !g_stop; s++)
			sleep(1);
	}
}

/* =========================================================================
 * Daemon lifecycle
 * ====================================================================== */

static int daemon_start(const char *fmt,
			 const char *tcp_target,
			 const char *http_uri,
			 bool insecure)
{
	pid_t pid = fork();

	if (pid < 0)
		return -1;

	if (pid > 0) {
		if (write_pid_file(pid) != 0)
			fprintf(stderr,
				"process watch: warning: failed to write PID file %s\n",
				ELA_PROCESS_WATCH_PID_FILE);
		return 0;
	}

	/* Daemon child */
	setsid();
	signal(SIGTERM, watch_signal_handler);
	signal(SIGINT,  watch_signal_handler);

	{
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO)
				close(devnull);
		}
	}

	if (tcp_target && *tcp_target)
		g_watch_sock = ela_connect_tcp_ipv4(tcp_target);

	g_watch_http_uri  = http_uri;
	g_watch_insecure  = insecure;

	poll_loop(fmt);

	if (g_watch_sock >= 0)
		close(g_watch_sock);

	unlink(ELA_PROCESS_WATCH_PID_FILE);
	exit(0);
}

static int daemon_stop(void)
{
	pid_t pid = read_pid_file();

	if (pid < 0) {
		fprintf(stderr,
			"process watch: not running (no PID file at %s)\n",
			ELA_PROCESS_WATCH_PID_FILE);
		return 1;
	}

	if (kill(pid, SIGTERM) != 0) {
		if (errno == ESRCH) {
			fprintf(stderr,
				"process watch: process %ld no longer exists; cleaning up\n",
				(long)pid);
			unlink(ELA_PROCESS_WATCH_PID_FILE);
			return 0;
		}
		fprintf(stderr, "process watch: failed to stop process %ld: %s\n",
			(long)pid, strerror(errno));
		return 1;
	}

	unlink(ELA_PROCESS_WATCH_PID_FILE);
	fprintf(stdout, "process watch stopped (pid=%ld)\n", (long)pid);
	return 0;
}

static bool daemon_is_running(void)
{
	pid_t pid = read_pid_file();

	return pid > 0 && kill(pid, 0) == 0;
}

/* =========================================================================
 * watch on / watch off / watch list
 * ====================================================================== */

static int cmd_watch_on(const char *needle,
			 const char *fmt,
			 const char *tcp_target,
			 const char *http_uri,
			 bool insecure)
{
	char needles[MAX_WATCH_ENTRIES][ELA_PROCESS_WATCH_NEEDLE_MAX + 1];
	char pids[MAX_WATCH_ENTRIES][ELA_PROCESS_WATCH_PIDS_MAX_LEN];
	int count = 0;
	int lock_fd;
	int i;

	if (!ela_process_watch_needle_is_valid(needle)) {
		fprintf(stderr, "process watch: invalid needle: '%s'\n"
			"  (must be non-empty, ≤%d bytes, no newlines or tabs)\n",
			needle ? needle : "(null)",
			ELA_PROCESS_WATCH_NEEDLE_MAX);
		return 2;
	}

	lock_fd = lock_acquire();
	if (lock_fd < 0) {
		fprintf(stderr, "process watch: failed to acquire lock\n");
		return 1;
	}

	state_read(needles, pids, &count, MAX_WATCH_ENTRIES);

	/* Check for duplicate */
	for (i = 0; i < count; i++) {
		if (!strcmp(needles[i], needle)) {
			lock_release(lock_fd);
			fprintf(stderr,
				"process watch: '%s' is already being watched\n",
				needle);
			return 1;
		}
	}

	if (count >= MAX_WATCH_ENTRIES) {
		lock_release(lock_fd);
		fprintf(stderr, "process watch: too many watched needles (max %d)\n",
			MAX_WATCH_ENTRIES);
		return 1;
	}

	snprintf(needles[count], ELA_PROCESS_WATCH_NEEDLE_MAX + 1, "%s", needle);
	pids[count][0] = '\0'; /* PIDs populated on first poll */
	count++;

	state_write(needles, pids, count);
	lock_release(lock_fd);

	if (!daemon_is_running()) {
		if (daemon_start(fmt, tcp_target, http_uri, insecure) != 0) {
			fprintf(stderr,
				"process watch: failed to start daemon: %s\n",
				strerror(errno));
			return 1;
		}
		fprintf(stdout, "process watch started\n");
	}

	fprintf(stdout, "process watch: now watching '%s'\n", needle);
	return 0;
}

static int cmd_watch_off(const char *needle)
{
	char needles[MAX_WATCH_ENTRIES][ELA_PROCESS_WATCH_NEEDLE_MAX + 1];
	char pids[MAX_WATCH_ENTRIES][ELA_PROCESS_WATCH_PIDS_MAX_LEN];
	int count = 0;
	int lock_fd;
	int found = -1;
	int i;
	int j;

	lock_fd = lock_acquire();
	if (lock_fd < 0) {
		fprintf(stderr, "process watch: failed to acquire lock\n");
		return 1;
	}

	state_read(needles, pids, &count, MAX_WATCH_ENTRIES);

	for (i = 0; i < count; i++) {
		if (!strcmp(needles[i], needle)) {
			found = i;
			break;
		}
	}

	if (found < 0) {
		lock_release(lock_fd);
		fprintf(stderr, "process watch: '%s' is not being watched\n", needle);
		return 1;
	}

	/* Shift remaining entries down */
	for (j = found; j < count - 1; j++) {
		memcpy(needles[j], needles[j + 1],
		       ELA_PROCESS_WATCH_NEEDLE_MAX + 1);
		memcpy(pids[j], pids[j + 1], ELA_PROCESS_WATCH_PIDS_MAX_LEN);
	}
	count--;

	if (state_write(needles, pids, count) < 0)
		fprintf(stderr, "process watch: failed to write state\n");
	lock_release(lock_fd);

	fprintf(stdout, "process watch: stopped watching '%s'\n", needle);

	if (count == 0)
		daemon_stop();

	return 0;
}

static int cmd_watch_list(const char *fmt)
{
	char needles[MAX_WATCH_ENTRIES][ELA_PROCESS_WATCH_NEEDLE_MAX + 1];
	char pids[MAX_WATCH_ENTRIES][ELA_PROCESS_WATCH_PIDS_MAX_LEN];
	int count = 0;
	int lock_fd;
	int i;

	lock_fd = lock_acquire();
	if (lock_fd < 0) {
		fprintf(stderr, "process watch: failed to acquire lock\n");
		return 1;
	}
	state_read(needles, pids, &count, MAX_WATCH_ENTRIES);
	lock_release(lock_fd);

	if (count == 0) {
		fprintf(stdout, "process watch: no needles registered\n");
		return 0;
	}

	for (i = 0; i < count; i++) {
		char current_pids[ELA_PROCESS_WATCH_PIDS_MAX_LEN];
		char *buf = NULL;
		size_t len = 0;

		/* Show live PIDs, not stale stored ones */
		if (scan_pids_for_needle(needles[i], current_pids,
					 sizeof(current_pids)) != 0)
			strncpy(current_pids, "(scan failed)",
				sizeof(current_pids) - 1);

		if (*current_pids == '\0')
			strncpy(current_pids, "(none)", sizeof(current_pids) - 1);

		if (ela_process_watch_format_list_entry(needles[i], current_pids,
							fmt, &buf, &len) == 0 &&
		    buf) {
			fwrite(buf, 1, len, stdout);
			free(buf);
		}
	}
	return 0;
}

/* =========================================================================
 * watch subcommand dispatcher
 * ====================================================================== */

static void usage_watch(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s watch on <needle>   Start watching processes matching <needle>\n"
		"  %s watch off <needle>  Stop watching processes matching <needle>\n"
		"  %s watch list          List all watched needles and their current PIDs\n"
		"\n"
		"  <needle> is matched against each process's full command line.\n"
		"  When a matching process's PID set changes (restart detected), a record\n"
		"  is emitted per --output-format (txt/csv/json) and forwarded to\n"
		"  --output-tcp or --output-http when configured.\n"
		"  Polls /proc every %ds.\n",
		prog, prog, prog, ELA_PROCESS_WATCH_POLL_SECS);
}

static int watch_main(int argc, char **argv,
		       const char *fmt,
		       const char *tcp_target,
		       const char *http_uri,
		       bool insecure)
{
	const char *action;
	const char *needle;

	/* argv[0] = "watch" */
	if (argc < 2 ||
	    !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		usage_watch(argv[0]);
		return (argc < 2) ? 2 : 0;
	}

	action = argv[1];

	if (!strcmp(action, "list")) {
		if (argc > 2) {
			fprintf(stderr, "process watch list: unexpected argument: %s\n",
				argv[2]);
			usage_watch(argv[0]);
			return 2;
		}
		return cmd_watch_list(fmt);
	}

	if (strcmp(action, "on") && strcmp(action, "off")) {
		fprintf(stderr, "process watch: expected 'on', 'off', or 'list', got: %s\n",
			action);
		usage_watch(argv[0]);
		return 2;
	}

	if (argc < 3) {
		fprintf(stderr, "process watch %s: missing <needle> argument\n", action);
		usage_watch(argv[0]);
		return 2;
	}

	needle = argv[2];

	if (!strcmp(action, "on"))
		return cmd_watch_on(needle, fmt, tcp_target, http_uri, insecure);

	return cmd_watch_off(needle);
}

/* =========================================================================
 * Top-level entry point: linux process ...
 * ====================================================================== */

static void usage_process(const char *prog)
{
	fprintf(stderr,
		"Usage: %s watch <on|off|list> [<needle>]\n"
		"  Process watching: track restart events for matching processes.\n",
		prog);
}

int linux_process_main(int argc, char **argv)
{
	const char *output_tcp   = getenv("ELA_OUTPUT_TCP");
	const char *output_http  = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *fmt          = getenv("ELA_OUTPUT_FORMAT");
	bool insecure = getenv("ELA_OUTPUT_INSECURE") &&
			!strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	const char *http_uri = NULL;

	if (!fmt || !*fmt)
		fmt = "txt";

	/* argv[0] = "process" */
	if (argc < 2 ||
	    !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		usage_process(argv[0]);
		return (argc < 2) ? 2 : 0;
	}

	if (!strcmp(argv[1], "watch")) {
		if (output_http && *output_http)
			http_uri = output_http;
		else if (output_https && *output_https)
			http_uri = output_https;

		return watch_main(argc - 1, argv + 1, fmt,
				  output_tcp, http_uri, insecure);
	}

	fprintf(stderr, "process: unknown subcommand: %s\n\n", argv[1]);
	usage_process(argv[0]);
	return 2;
}
