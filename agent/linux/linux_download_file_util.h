// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_LINUX_DOWNLOAD_FILE_UTIL_H
#define ELA_LINUX_DOWNLOAD_FILE_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

struct ela_download_file_env {
	bool insecure;
	bool verbose;
};

struct ela_download_file_request {
	const char *url;
	const char *output_path;
	bool insecure;
	bool verbose;
	bool show_help;
};

struct ela_download_file_result {
	uint64_t downloaded_bytes;
	bool success;
};

struct ela_download_file_ops {
	int (*http_get_to_file_fn)(const char *uri, const char *output_path,
				   bool insecure, bool verbose,
				   char *errbuf, size_t errbuf_len);
	int (*stat_fn)(const char *path, struct stat *st);
};

int ela_download_file_prepare_request(int argc, char **argv,
				      const struct ela_download_file_env *env,
				      struct ela_download_file_request *out,
				      char *errbuf, size_t errbuf_len);

int ela_download_file_format_summary(char *buf, size_t buf_sz,
				     const struct ela_download_file_result *result,
				     const struct ela_download_file_request *request);

int ela_download_file_run(const struct ela_download_file_request *request,
			  const struct ela_download_file_ops *ops,
			  struct ela_download_file_result *result,
			  char *errbuf, size_t errbuf_len);

#endif
