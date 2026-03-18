// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_REMOTE_COPY_CMD_UTIL_H
#define ELA_REMOTE_COPY_CMD_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

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
