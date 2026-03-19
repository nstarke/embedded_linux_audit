// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "transfer_cmd_util.h"

#include "../embedded_linux_audit_cmd.h"
#include "../net/ws_url_util.h"
#include "../shell/interactive.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#define TRANSFER_RETRY_DELAY_SECS 60

static int default_write_stdout(const char *message)
{
	if (!message)
		return -1;
	return fputs(message, stdout) < 0 ? -1 : 0;
}

static int default_write_stderr(const char *message)
{
	if (!message)
		return -1;
	return fputs(message, stderr) < 0 ? -1 : 0;
}

static unsigned int default_sleep(unsigned int seconds)
{
	return sleep(seconds);
}

#ifdef ELA_AGENT_UNIT_TESTS
static int default_is_ws_url(const char *url)
{
	(void)url;
	return 0;
}

static int default_ws_connect(const char *base_url, int insecure, struct ela_ws_conn *ws_out)
{
	(void)base_url;
	(void)insecure;
	(void)ws_out;
	return -1;
}

static void default_ws_close_parent_fd(const struct ela_ws_conn *ws)
{
	(void)ws;
}

static void default_ws_close(struct ela_ws_conn *ws)
{
	(void)ws;
}

static int default_ws_run_interactive(struct ela_ws_conn *ws, const char *prog)
{
	(void)ws;
	(void)prog;
	return 0;
}

static int default_connect_tcp_any(const char *spec)
{
	(void)spec;
	return -1;
}

static int default_send_all(int sock, const uint8_t *buf, size_t len)
{
	(void)sock;
	(void)buf;
	(void)len;
	return -1;
}

static int default_interactive_loop(const char *prog)
{
	(void)prog;
	return 0;
}
#else
static int default_is_ws_url(const char *url)
{
	return ela_is_ws_url(url);
}

static int default_ws_connect(const char *base_url, int insecure, struct ela_ws_conn *ws_out)
{
	return ela_ws_connect(base_url, insecure, ws_out);
}

static void default_ws_close_parent_fd(const struct ela_ws_conn *ws)
{
	ela_ws_close_parent_fd(ws);
}

static void default_ws_close(struct ela_ws_conn *ws)
{
	ela_ws_close(ws);
}

static int default_ws_run_interactive(struct ela_ws_conn *ws, const char *prog)
{
	return ela_ws_run_interactive(ws, prog);
}

static int default_connect_tcp_any(const char *spec)
{
	return ela_connect_tcp_any(spec);
}

static int default_send_all(int sock, const uint8_t *buf, size_t len)
{
	return ela_send_all(sock, buf, len);
}

static int default_interactive_loop(const char *prog)
{
	return interactive_loop(prog);
}
#endif

static int default_open_readonly(const char *path, int flags)
{
	return open(path, flags);
}

static int default_run_tcp_child_session(const struct ela_transfer_request *request,
					 int sock,
					 const struct ela_transfer_tcp_child_ops *child_ops);

static const struct ela_transfer_ws_ops default_ws_ops = {
	.is_ws_url_fn = default_is_ws_url,
	.ws_connect_fn = default_ws_connect,
	.ws_close_parent_fd_fn = default_ws_close_parent_fd,
	.ws_close_fn = default_ws_close,
	.ws_run_interactive_fn = default_ws_run_interactive,
	.fork_fn = fork,
	.setsid_fn = setsid,
	.sleep_fn = default_sleep,
	.write_stdout_fn = default_write_stdout,
	.write_stderr_fn = default_write_stderr,
};

static const struct ela_transfer_tcp_child_ops default_tcp_child_ops = {
	.open_fn = default_open_readonly,
	.read_fn = read,
	.send_all_fn = default_send_all,
	.dup2_fn = dup2,
	.close_fn = close,
	.interactive_loop_fn = default_interactive_loop,
};

static const struct ela_transfer_tcp_ops default_tcp_ops = {
	.connect_tcp_any_fn = default_connect_tcp_any,
	.fork_fn = fork,
	.setsid_fn = setsid,
	.close_fn = close,
	.write_stdout_fn = default_write_stdout,
	.write_stderr_fn = default_write_stderr,
	.run_child_session_fn = default_run_tcp_child_session,
	.child_ops = &default_tcp_child_ops,
};

static void set_errbuf(char *errbuf, size_t errbuf_len, const char *fmt, ...)
{
	va_list ap;

	if (!errbuf || errbuf_len == 0 || !fmt)
		return;

	va_start(ap, fmt);
	vsnprintf(errbuf, errbuf_len, fmt, ap);
	va_end(ap);
}

static int write_pid_message(int (*write_fn)(const char *message), pid_t pid)
{
	char message[96];

	snprintf(message, sizeof(message), "Transfer started (pid=%ld)\n", (long)pid);
	return write_fn ? write_fn(message) : 0;
}

int ela_transfer_run_ws(const struct ela_transfer_request *request,
			const struct ela_transfer_ws_ops *ops,
			struct ela_transfer_result *result,
			char *errbuf,
			size_t errbuf_len)
{
	const struct ela_transfer_ws_ops *effective_ops = ops ? ops : &default_ws_ops;
	struct ela_ws_conn ws;
	pid_t pid;
	int failed_attempts = 0;

	if (!request || !request->options.target)
		return 1;

	memset(&ws, 0, sizeof(ws));
	if (result)
		memset(result, 0, sizeof(*result));

	if (effective_ops->ws_connect_fn(request->options.target, request->options.insecure, &ws) != 0) {
		set_errbuf(errbuf, errbuf_len, "transfer: failed to connect to %s", request->options.target);
		return 1;
	}

	pid = effective_ops->fork_fn();
	if (pid < 0) {
		effective_ops->ws_close_parent_fd_fn(&ws);
		set_errbuf(errbuf, errbuf_len, "transfer: fork failed: %s", strerror(errno));
		return 1;
	}

	if (pid > 0) {
		effective_ops->ws_close_parent_fd_fn(&ws);
		write_pid_message(effective_ops->write_stdout_fn, pid);
		if (result) {
			result->started = true;
			result->used_websocket = true;
			result->started_pid = pid;
		}
		return 0;
	}

	effective_ops->setsid_fn();
	for (;;) {
		int rc = effective_ops->ws_run_interactive_fn(&ws, request->prog);
		if (rc == ELA_WS_EXIT_CLEAN) {
			effective_ops->ws_close_fn(&ws);
			if (result) {
				result->used_websocket = true;
				result->exit_code = 0;
			}
			return 0;
		}
		effective_ops->ws_close_fn(&ws);

		if (request->options.retry_attempts == 0)
			break;

		for (;;) {
			char message[128];

			failed_attempts++;
			if (failed_attempts > request->options.retry_attempts)
				break;

			snprintf(message, sizeof(message),
				 "transfer: reconnect attempt %d/%d, waiting %ds\n",
				 failed_attempts, request->options.retry_attempts,
				 TRANSFER_RETRY_DELAY_SECS);
			if (effective_ops->write_stderr_fn)
				effective_ops->write_stderr_fn(message);
			effective_ops->sleep_fn(TRANSFER_RETRY_DELAY_SECS);
			if (effective_ops->ws_connect_fn(request->options.target,
							 request->options.insecure, &ws) == 0) {
				if (result)
					result->reconnect_attempts = failed_attempts;
				failed_attempts = 0;
				break;
			}

			snprintf(message, sizeof(message),
				 "transfer: failed to connect to %s\n",
				 request->options.target);
			if (effective_ops->write_stderr_fn)
				effective_ops->write_stderr_fn(message);
		}

		if (failed_attempts > request->options.retry_attempts)
			break;
	}

	if (effective_ops->write_stderr_fn) {
		char message[128];
		snprintf(message, sizeof(message),
			 "transfer: max retry attempts (%d) reached, exiting\n",
			 request->options.retry_attempts);
		effective_ops->write_stderr_fn(message);
	}
	if (result) {
		result->used_websocket = true;
		result->exit_code = 1;
		result->reconnect_attempts = failed_attempts;
	}
	return 1;
}

int ela_transfer_run_tcp_child(const struct ela_transfer_request *request,
			       int sock,
			       const struct ela_transfer_tcp_child_ops *ops)
{
	const struct ela_transfer_tcp_child_ops *effective_ops = ops ? ops : &default_tcp_child_ops;
	uint8_t buf[65536];
	ssize_t n;
	int fd;

	if (!request || !request->self_exe_path)
		return 1;

	fd = effective_ops->open_fn(request->self_exe_path, O_RDONLY);
	if (fd < 0)
		return 1;

	for (;;) {
		n = effective_ops->read_fn(fd, buf, sizeof(buf));
		if (n < 0) {
			effective_ops->close_fn(fd);
			effective_ops->close_fn(sock);
			return 1;
		}
		if (n == 0)
			break;
		if (effective_ops->send_all_fn(sock, buf, (size_t)n) < 0) {
			effective_ops->close_fn(fd);
			effective_ops->close_fn(sock);
			return 1;
		}
	}
	effective_ops->close_fn(fd);

	if (effective_ops->dup2_fn(sock, STDIN_FILENO) < 0 ||
	    effective_ops->dup2_fn(sock, STDOUT_FILENO) < 0 ||
	    effective_ops->dup2_fn(sock, STDERR_FILENO) < 0) {
		effective_ops->close_fn(sock);
		return 1;
	}
	effective_ops->close_fn(sock);

	return effective_ops->interactive_loop_fn(request->prog);
}

static int default_run_tcp_child_session(const struct ela_transfer_request *request,
					 int sock,
					 const struct ela_transfer_tcp_child_ops *child_ops)
{
	return ela_transfer_run_tcp_child(request, sock, child_ops);
}

int ela_transfer_run_tcp(const struct ela_transfer_request *request,
			 const struct ela_transfer_tcp_ops *ops,
			 struct ela_transfer_result *result,
			 char *errbuf,
			 size_t errbuf_len)
{
	const struct ela_transfer_tcp_ops *effective_ops = ops ? ops : &default_tcp_ops;
	int sock;
	pid_t pid;

	if (!request || !request->options.target)
		return 1;

	if (result)
		memset(result, 0, sizeof(*result));

	sock = effective_ops->connect_tcp_any_fn(request->options.target);
	if (sock < 0) {
		set_errbuf(errbuf, errbuf_len, "transfer: failed to connect to %s", request->options.target);
		return 1;
	}

	pid = effective_ops->fork_fn();
	if (pid < 0) {
		effective_ops->close_fn(sock);
		set_errbuf(errbuf, errbuf_len, "transfer: fork failed: %s", strerror(errno));
		return 1;
	}

	if (pid > 0) {
		effective_ops->close_fn(sock);
		write_pid_message(effective_ops->write_stdout_fn, pid);
		if (result) {
			result->started = true;
			result->started_pid = pid;
		}
		return 0;
	}

	effective_ops->setsid_fn();
	if (result)
		result->exit_code = effective_ops->run_child_session_fn(request, sock, effective_ops->child_ops);
	else
		(void)effective_ops->run_child_session_fn(request, sock, effective_ops->child_ops);
	return result ? result->exit_code : 0;
}

int ela_transfer_execute(const struct ela_transfer_request *request,
			 const struct ela_transfer_ws_ops *ws_ops,
			 const struct ela_transfer_tcp_ops *tcp_ops,
			 struct ela_transfer_result *result,
			 char *errbuf,
			 size_t errbuf_len)
{
	const struct ela_transfer_ws_ops *effective_ws_ops = ws_ops ? ws_ops : &default_ws_ops;

	if (!request || !request->options.target)
		return 1;

	if (effective_ws_ops->is_ws_url_fn(request->options.target)) {
		return ela_transfer_run_ws(request, effective_ws_ops, result, errbuf, errbuf_len);
	}
	return ela_transfer_run_tcp(request, tcp_ops ? tcp_ops : &default_tcp_ops,
				    result, errbuf, errbuf_len);
}
