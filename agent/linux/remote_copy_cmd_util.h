// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_REMOTE_COPY_CMD_UTIL_H
#define ELA_REMOTE_COPY_CMD_UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>

struct ela_remote_copy_env {
	const char *output_tcp;
	const char *output_http;
	const char *output_https;
	bool insecure;
	bool verbose;
};

struct ela_remote_copy_request {
	const char *path;
	const char *output_tcp;
	const char *output_http;
	const char *output_https;
	const char *output_uri;
	bool recursive;
	bool allow_dev;
	bool allow_sysfs;
	bool allow_proc;
	bool allow_symlinks;
	bool insecure;
	bool verbose;
	bool show_help;
};

struct ela_remote_copy_execution_result {
	uint64_t copied_files;
	bool emitted_summary;
};

struct ela_remote_copy_execution_ops {
	int (*stat_fn)(const char *path, struct stat *st);
	int (*validate_request_fn)(const char *path,
				   const char *output_tcp,
				   const char *output_http,
				   const char *output_https,
				   mode_t mode,
				   char *errbuf,
				   size_t errbuf_len);
	bool (*path_is_allowed_fn)(const char *path, bool allow_dev, bool allow_sysfs, bool allow_proc);
	bool (*stat_is_copyable_file_fn)(const struct stat *st);
	int (*send_file_to_tcp_fn)(const char *path, const char *output_tcp, bool verbose);
	int (*upload_path_http_fn)(const char *path,
				   const char *output_uri,
				   bool insecure,
				   bool verbose,
				   bool recursive,
				   bool allow_dev,
				   bool allow_sysfs,
				   bool allow_proc,
				   bool allow_symlinks,
				   uint64_t *copied_files);
	int (*format_summary_fn)(char *buf, size_t buf_sz, const char *path, uint64_t copied_files);
	int (*write_stderr_fn)(const char *message);
};

int ela_remote_copy_prepare_request(int argc, char **argv,
				    const struct ela_remote_copy_env *env,
				    struct ela_remote_copy_request *out,
				    char *errbuf,
				    size_t errbuf_len);

int ela_remote_copy_execute(const struct ela_remote_copy_request *request,
			    const struct ela_remote_copy_execution_ops *ops,
			    struct ela_remote_copy_execution_result *result,
			    char *errbuf,
			    size_t errbuf_len);

int ela_remote_copy_validate_request(const char *path,
				     const char *output_tcp,
				     const char *output_http,
				     const char *output_https,
				     mode_t mode,
				     char *errbuf,
				     size_t errbuf_len);
int ela_remote_copy_format_errno_message(char *buf,
					 size_t buf_sz,
					 const char *fmt,
					 const char *path,
					 int errnum);
int ela_remote_copy_join_child_path(const char *parent,
				    const char *name,
				    char *buf,
				    size_t buf_sz);
bool ela_remote_copy_should_recurse(mode_t mode, bool recursive);

#endif
