// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_FILE_IO_UTIL_H
#define ELA_FILE_IO_UTIL_H

#include <stddef.h>

/* Write every byte, retrying interrupted writes; return -1 on error or EOF. */
int ela_write_all(int fd, const unsigned char *data, size_t len);
/* Read a symlink basename, truncating to fit and NUL-terminating on success. */
int ela_readlink_basename(const char *path, char *out, size_t outsz);

#endif
