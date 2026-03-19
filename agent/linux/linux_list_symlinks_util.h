// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_LINUX_LIST_SYMLINKS_UTIL_H
#define ELA_LINUX_LIST_SYMLINKS_UTIL_H

#include "../util/output_buffer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

struct ela_list_symlinks_env {
	const char *output_format;
	const char *output_tcp;
	const char *output_http;
	const char *output_https;
	bool insecure;
};

struct ela_list_symlinks_request {
	const char *dir_path;
	const char *output_format;
	const char *output_uri;
	bool recursive;
	bool insecure;
	bool show_help;
	int output_sock;
};

struct ela_list_symlinks_prepare_ops {
	int (*parse_http_output_uri_fn)(const char *uri,
					 const char **output_http,
					 const char **output_https,
					 char *errbuf,
					 size_t errbuf_len);
	int (*connect_tcp_ipv4_fn)(const char *spec);
	int (*lstat_fn)(const char *path, struct stat *st);
};

struct ela_list_symlinks_run_ops {
	int (*lstat_fn)(const char *path, struct stat *st);
	ssize_t (*readlink_fn)(const char *path, char *buf, size_t bufsz);
	int (*format_symlink_record_fn)(struct output_buffer *out,
					 const char *format,
					 const char *link_path,
					 const char *target_path);
	int (*send_all_fn)(int sock, const uint8_t *buf, size_t len);
	int (*append_output_fn)(struct output_buffer *buf, const char *data, size_t len);
	int (*write_stdout_fn)(const char *data, size_t len);
	char *(*build_upload_uri_fn)(const char *base_uri, const char *upload_type, const char *file_path);
	const char *(*content_type_fn)(const char *format, const char *default_content_type);
	int (*http_post_fn)(const char *uri, const uint8_t *data, size_t len,
				 const char *content_type, bool insecure, bool verbose,
				 char *errbuf, size_t errbuf_len);
	int (*http_post_log_message_fn)(const char *base_uri, const char *message,
					 bool insecure, bool verbose,
					 char *errbuf, size_t errbuf_len);
	int (*close_fn)(int fd);
};

int ela_list_symlinks_prepare_request(int argc, char **argv,
				      const struct ela_list_symlinks_env *env,
				      const struct ela_list_symlinks_prepare_ops *ops,
				      struct ela_list_symlinks_request *out,
				      char *errbuf, size_t errbuf_len);

int ela_list_symlinks_run(const struct ela_list_symlinks_request *request,
			  const struct ela_list_symlinks_run_ops *ops,
			  char *errbuf, size_t errbuf_len);

#endif
