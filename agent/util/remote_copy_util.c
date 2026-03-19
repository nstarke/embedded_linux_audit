// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "remote_copy_util.h"

#include "str_util.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool ela_has_path_prefix(const char *path, const char *prefix)
{
	size_t prefix_len;

	if (!path || !prefix)
		return false;

	prefix_len = strlen(prefix);
	if (strncmp(path, prefix, prefix_len))
		return false;

	return path[prefix_len] == '\0' || path[prefix_len] == '/';
}

bool ela_path_is_allowed(const char *path, bool allow_dev, bool allow_sysfs, bool allow_proc)
{
	if (ela_has_path_prefix(path, "/dev"))
		return allow_dev;
	if (ela_has_path_prefix(path, "/sys"))
		return allow_sysfs;
	if (ela_has_path_prefix(path, "/proc"))
		return allow_proc;
	return true;
}

bool ela_stat_is_copyable_file(const struct stat *st)
{
	if (!st)
		return false;

	return S_ISREG(st->st_mode) || S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode);
}

int ela_format_remote_copy_summary(char *buf, size_t buf_sz, const char *path, uint64_t copied_files)
{
	int n;

	if (!buf || buf_sz == 0 || !path)
		return -1;

	n = snprintf(buf, buf_sz, "remote-copy copied path %s (%" PRIu64 " file%s copied)\n",
		     path, copied_files, copied_files == 1 ? "" : "s");
	if (n < 0 || (size_t)n >= buf_sz)
		return -1;
	return 0;
}

char *ela_remote_copy_build_symlink_upload_uri(const char *upload_uri, const char *target_path)
{
	char *escaped_target;
	char *final_uri;
	size_t final_len;

	if (!upload_uri || !target_path)
		return NULL;

	escaped_target = url_percent_encode(target_path);
	if (!escaped_target)
		return NULL;

	final_len = strlen(upload_uri) + strlen("&symlink=true&symlinkPath=") + strlen(escaped_target) + 1U;
	final_uri = malloc(final_len);
	if (!final_uri) {
		free(escaped_target);
		return NULL;
	}

	snprintf(final_uri, final_len, "%s&symlink=true&symlinkPath=%s", upload_uri, escaped_target);
	free(escaped_target);
	return final_uri;
}
