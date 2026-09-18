// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "file_io_util.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

int ela_write_all(int fd, const unsigned char *data, size_t len)
{
	size_t offset = 0;

	while (offset < len) {
		ssize_t written;

		do {
			written = write(fd, data + offset, len - offset);
		} while (written < 0 && errno == EINTR);
		/* write(2) never returns more than it was asked for, but bound
		 * it anyway so offset can never exceed len and len - offset can
		 * never underflow (Coverity INTEGER_OVERFLOW on the write() arg). */
		if (written <= 0 || (size_t)written > len - offset)
			return -1;
		offset += (size_t)written;
	}
	return 0;
}

int ela_readlink_basename(const char *path, char *out, size_t outsz)
{
	char buf[512];
	const char *base;
	size_t len;
	ssize_t n = readlink(path, buf, sizeof(buf) - 1);

	if (n < 0 || outsz == 0)
		return -1;
	buf[n] = '\0';
	base = strrchr(buf, '/');
	base = base ? base + 1 : buf;
	len = strlen(base);
	if (len >= outsz)
		len = outsz - 1;
	memcpy(out, base, len);
	out[len] = '\0';
	return 0;
}
