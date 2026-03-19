// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_TRANSFER_CMD_UTIL_H
#define ELA_TRANSFER_CMD_UTIL_H

#include "../net/ws_client.h"
#include "../util/transfer_parse_util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct ela_transfer_request {
	const char *prog;
	const char *self_exe_path;
	struct ela_transfer_options options;
};

struct ela_transfer_result {
	bool started;
	bool used_websocket;
	pid_t started_pid;
	int exit_code;
	int reconnect_attempts;
};

struct ela_transfer_ws_ops {
	int (*is_ws_url_fn)(const char *url);
	int (*ws_connect_fn)(const char *base_url, int insecure, struct ela_ws_conn *ws_out);
	void (*ws_close_parent_fd_fn)(const struct ela_ws_conn *ws);
	void (*ws_close_fn)(struct ela_ws_conn *ws);
	int (*ws_run_interactive_fn)(struct ela_ws_conn *ws, const char *prog);
	pid_t (*fork_fn)(void);
	pid_t (*setsid_fn)(void);
	unsigned int (*sleep_fn)(unsigned int seconds);
	int (*write_stdout_fn)(const char *message);
	int (*write_stderr_fn)(const char *message);
};

struct ela_transfer_tcp_child_ops {
	int (*open_fn)(const char *path, int flags);
	ssize_t (*read_fn)(int fd, void *buf, size_t count);
	int (*send_all_fn)(int sock, const uint8_t *buf, size_t len);
	int (*dup2_fn)(int oldfd, int newfd);
	int (*close_fn)(int fd);
	int (*interactive_loop_fn)(const char *prog);
};

struct ela_transfer_tcp_ops {
	int (*connect_tcp_any_fn)(const char *spec);
	pid_t (*fork_fn)(void);
	pid_t (*setsid_fn)(void);
	int (*close_fn)(int fd);
	int (*write_stdout_fn)(const char *message);
	int (*write_stderr_fn)(const char *message);
	int (*run_child_session_fn)(const struct ela_transfer_request *request,
				    int sock,
				    const struct ela_transfer_tcp_child_ops *child_ops);
	const struct ela_transfer_tcp_child_ops *child_ops;
};

int ela_transfer_run_ws(const struct ela_transfer_request *request,
			const struct ela_transfer_ws_ops *ops,
			struct ela_transfer_result *result,
			char *errbuf,
			size_t errbuf_len);

int ela_transfer_run_tcp_child(const struct ela_transfer_request *request,
			       int sock,
			       const struct ela_transfer_tcp_child_ops *ops);

int ela_transfer_run_tcp(const struct ela_transfer_request *request,
			 const struct ela_transfer_tcp_ops *ops,
			 struct ela_transfer_result *result,
			 char *errbuf,
			 size_t errbuf_len);

int ela_transfer_execute(const struct ela_transfer_request *request,
			 const struct ela_transfer_ws_ops *ws_ops,
			 const struct ela_transfer_tcp_ops *tcp_ops,
			 struct ela_transfer_result *result,
			 char *errbuf,
			 size_t errbuf_len);

#endif
