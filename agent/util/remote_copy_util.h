// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_REMOTE_COPY_UTIL_H
#define UTIL_REMOTE_COPY_UTIL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

bool ela_has_path_prefix(const char *path, const char *prefix);
bool ela_path_is_allowed(const char *path, bool allow_dev, bool allow_sysfs, bool allow_proc);
bool ela_stat_is_copyable_file(const struct stat *st);
int ela_format_remote_copy_summary(char *buf, size_t buf_sz, const char *path, uint64_t copied_files);
char *ela_remote_copy_build_symlink_upload_uri(const char *upload_uri, const char *target_path);

#endif
