// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_LIFECYCLE_UTIL_H
#define UTIL_LIFECYCLE_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/*
 * Injectable I/O operations for ela_emit_lifecycle_event_ex.
 * Pass NULL to use the production defaults.
 */
struct ela_lifecycle_io_ops {
	time_t  (*time_fn)(time_t *t);
	ssize_t (*write_fn)(int fd, const void *buf, size_t len);
	int     (*connect_tcp_fn)(const char *spec);
	int     (*send_all_fn)(int sock, const uint8_t *buf, size_t len);
	int     (*close_fn)(int fd);
	char   *(*build_upload_uri_fn)(const char *base_uri,
				       const char *upload_type,
				       const char *file_path);
	int     (*http_post_fn)(const char *uri,
				const uint8_t *data, size_t len,
				const char *content_type,
				bool insecure, bool verbose,
				char *errbuf, size_t errbuf_len);
};

/*
 * Emit a lifecycle event with injectable I/O.  The caller is responsible
 * for checking whether lifecycle logging is enabled before invoking this.
 */
int ela_emit_lifecycle_event_ex(const struct ela_lifecycle_io_ops *ops,
				const char *output_format,
				const char *output_tcp,
				const char *output_http,
				const char *output_https,
				bool insecure,
				const char *command,
				const char *phase,
				int rc);

#endif /* UTIL_LIFECYCLE_UTIL_H */
