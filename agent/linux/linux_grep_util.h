// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_LINUX_GREP_UTIL_H
#define ELA_LINUX_GREP_UTIL_H

#include "../util/output_buffer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

struct ela_grep_env {
	const char *output_tcp;
	const char *output_http;
	const char *output_https;
	bool insecure;
};

struct ela_grep_request {
	const char *search;
	const char *dir_path;
	const char *output_uri;
	bool recursive;
	bool insecure;
	bool show_help;
	int output_sock;
};

struct ela_grep_prepare_ops {
	int (*parse_http_output_uri_fn)(const char *uri,
					 const char **output_http,
					 const char **output_https,
					 char *errbuf,
					 size_t errbuf_len);
	int (*connect_tcp_ipv4_fn)(const char *spec);
	int (*lstat_fn)(const char *path, struct stat *st);
};

struct ela_grep_run_ops {
	FILE *(*fopen_fn)(const char *path, const char *mode);
	ssize_t (*getline_fn)(char **lineptr, size_t *n, FILE *stream);
	int (*fclose_fn)(FILE *stream);
	int (*lstat_fn)(const char *path, struct stat *st);
	int (*format_grep_match_record_fn)(struct output_buffer *out,
					 const char *path,
					 unsigned long line_no,
					 const char *line);
	int (*send_all_fn)(int sock, const uint8_t *buf, size_t len);
	int (*append_output_fn)(struct output_buffer *buf, const char *data, size_t len);
	int (*write_stdout_fn)(const char *data, size_t len);
	char *(*build_upload_uri_fn)(const char *base_uri, const char *upload_type, const char *file_path);
	int (*http_post_fn)(const char *uri, const uint8_t *data, size_t len,
				 const char *content_type, bool insecure, bool verbose,
				 char *errbuf, size_t errbuf_len);
	int (*http_post_log_message_fn)(const char *base_uri, const char *message,
					 bool insecure, bool verbose,
					 char *errbuf, size_t errbuf_len);
	int (*close_fn)(int fd);
};

int ela_grep_prepare_request(int argc, char **argv,
			     const struct ela_grep_env *env,
			     const struct ela_grep_prepare_ops *ops,
			     struct ela_grep_request *out,
			     char *errbuf, size_t errbuf_len);

int ela_grep_run(const struct ela_grep_request *request,
		 const struct ela_grep_run_ops *ops,
		 char *errbuf, size_t errbuf_len);

#endif
