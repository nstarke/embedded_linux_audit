// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_LINUX_EXECUTE_COMMAND_UTIL_H
#define ELA_LINUX_EXECUTE_COMMAND_UTIL_H

#include "../util/output_buffer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>

struct ela_execute_command_env {
	const char *output_format;
	const char *output_tcp;
	const char *output_http;
	const char *output_https;
	bool insecure;
};

struct ela_execute_command_request {
	const char *command;
	const char *output_format;
	const char *output_tcp;
	const char *output_uri;
	bool insecure;
	bool show_help;
	int output_sock;
};

struct ela_execute_command_prepare_ops {
	int (*parse_http_output_uri_fn)(const char *uri,
					 const char **output_http,
					 const char **output_https,
					 char *errbuf,
					 size_t errbuf_len);
	int (*connect_tcp_ipv4_fn)(const char *spec);
};

struct ela_execute_command_capture_ops {
	FILE *(*popen_fn)(const char *command, const char *mode);
	size_t (*fread_fn)(void *ptr, size_t size, size_t nmemb, FILE *stream);
	int (*ferror_fn)(FILE *stream);
	int (*pclose_fn)(FILE *stream);
	int (*append_output_fn)(struct output_buffer *buf, const char *data, size_t len);
	int (*format_record_fn)(struct output_buffer *out,
				 const char *output_format,
				 const char *command,
				 const char *raw_text);
	int (*write_stdout_fn)(const char *data, size_t len);
	int (*send_all_fn)(int sock, const uint8_t *buf, size_t len);
	char *(*build_upload_uri_fn)(const char *base_uri, const char *upload_type, const char *file_path);
	const char *(*content_type_fn)(const char *output_format);
	int (*http_post_fn)(const char *uri, const uint8_t *data, size_t len,
				 const char *content_type, bool insecure, bool verbose,
				 char *errbuf, size_t errbuf_len);
	int (*close_fn)(int fd);
};

struct ela_execute_command_interactive_ops {
	void (*flush_stdout_fn)(void);
	void (*flush_stderr_fn)(void);
#ifdef __linux__
	pid_t (*forkpty_fn)(int *master_fd, char *name, const void *termios_p, const void *winsize_p);
#else
	pid_t (*fork_fn)(void);
#endif
	pid_t (*waitpid_fn)(pid_t pid, int *status, int options);
	int (*select_fn)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
			 struct timeval *timeout);
	ssize_t (*read_fn)(int fd, void *buf, size_t len);
	ssize_t (*write_fn)(int fd, const void *buf, size_t len);
	int (*close_fn)(int fd);
	int (*exec_shell_fn)(const char *command);
};

int ela_execute_command_prepare_request(int argc, char **argv,
					const struct ela_execute_command_env *env,
					bool stdout_is_tty,
					const struct ela_execute_command_prepare_ops *ops,
					struct ela_execute_command_request *out,
					char *errbuf, size_t errbuf_len);

bool ela_execute_command_should_run_interactive(const struct ela_execute_command_request *request,
						bool stdout_is_tty);

int ela_execute_command_run_capture(const struct ela_execute_command_request *request,
				    const struct ela_execute_command_capture_ops *ops,
				    char *errbuf, size_t errbuf_len);

int ela_execute_command_run_interactive_with_ops(const char *command,
						 const struct ela_execute_command_interactive_ops *ops);

#endif
