// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef AGENT_LINUX_LINUX_COREDUMP_UTIL_H
#define AGENT_LINUX_LINUX_COREDUMP_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define ELA_COREDUMP_DEFAULT_OUTPUT_DIR  "/tmp"
#define ELA_COREDUMP_DEFAULT_CONFIG_PATH "/tmp/ela-coredump.conf"

struct ela_coredump_config_request {
	const char *collector_path;
	const char *output_dir;
	const char *config_path;
	const char *output_uri;
	const char *api_key;
	bool insecure;
};

struct ela_coredump_collect_request {
	const char *output_dir;
	const char *config_path;
	const char *pid;
	const char *signal;
	const char *timestamp;
	const char *exe_name;
	bool insecure;
};

struct ela_coredump_config_file {
	char output_uri[512];
	char api_key[1024 + 1];
	bool insecure;
};

struct ela_coredump_ops {
	int (*mkdir_fn)(const char *path, unsigned int mode);
	int (*chmod_fn)(const char *path, unsigned int mode);
	int (*write_text_file_fn)(const char *path, const char *text, unsigned int mode);
	int (*read_text_file_fn)(const char *path, char *buf, size_t buf_len);
	ssize_t (*read_fn)(int fd, void *buf, size_t count);
	ssize_t (*write_fn)(int fd, const void *buf, size_t count);
	int (*open_file_fn)(const char *path, int flags, unsigned int mode);
	int (*close_fn)(int fd);
	time_t (*time_fn)(time_t *tloc);
	char *(*build_upload_uri_fn)(const char *base_uri, const char *upload_type,
				     const char *file_path);
	int (*http_post_fn)(const char *uri, const uint8_t *data, size_t len,
			    const char *content_type, bool insecure, bool verbose,
			    char *errbuf, size_t errbuf_len);
	void (*api_key_init_fn)(const char *api_key);
};

int ela_coredump_build_core_pattern(const char *collector_path, const char *output_dir,
				    char *out, size_t out_len);
int ela_coredump_write_config(const struct ela_coredump_config_request *request,
			      const struct ela_coredump_ops *ops,
			      char *errbuf, size_t errbuf_len);
int ela_coredump_read_config(const char *config_path,
			     const struct ela_coredump_ops *ops,
			     struct ela_coredump_config_file *out,
			     char *errbuf, size_t errbuf_len);
int ela_coredump_configure(const struct ela_coredump_config_request *request,
			   const struct ela_coredump_ops *ops,
			   char *errbuf, size_t errbuf_len);
int ela_coredump_disable(const char *config_path,
			 const struct ela_coredump_ops *ops,
			 char *errbuf, size_t errbuf_len);
int ela_coredump_collect(const struct ela_coredump_collect_request *request,
			 const struct ela_coredump_ops *ops,
			 char *out_path, size_t out_path_len,
			 char *errbuf, size_t errbuf_len);

#endif /* AGENT_LINUX_LINUX_COREDUMP_UTIL_H */
