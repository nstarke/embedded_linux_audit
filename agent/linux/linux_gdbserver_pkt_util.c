// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_gdbserver_pkt_util.h"

#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* -----------------------------------------------------------------------
 * Thread-id parser (handles both "p<pid>.<tid>" and plain "<tid>")
 * ---------------------------------------------------------------------- */

int ela_gdb_parse_thread_id(const char *s, pid_t *out_pid, pid_t *out_tid)
{
	unsigned long long p, t;
	int n = 0;

	if (!s || !*s)
		return -1;

	if (s[0] == 'p') {
		if (sscanf(s + 1, "%llx.%llx%n", &p, &t, &n) == 2) {
			if (out_pid) *out_pid = (pid_t)p;
			if (out_tid) *out_tid = (pid_t)t;
			return 1 + n;
		}
		return -1;
	}

	if (sscanf(s, "%llx%n", &t, &n) == 1) {
		if (out_pid) *out_pid = 0;
		if (out_tid) *out_tid = (pid_t)t;
		return n;
	}
	return -1;
}

/* -----------------------------------------------------------------------
 * RSP binary-escape decoder
 * ---------------------------------------------------------------------- */

int ela_gdb_rsp_binary_unescape(const char *src, size_t max_src,
				uint8_t *dst, size_t expected)
{
	size_t in = 0, out = 0;

	while (out < expected) {
		if (in >= max_src)
			return -1;
		if ((unsigned char)src[in] == 0x7du) {
			in++;
			if (in >= max_src)
				return -1;
			dst[out++] = (uint8_t)((unsigned char)src[in] ^ 0x20u);
		} else {
			dst[out++] = (uint8_t)(unsigned char)src[in];
		}
		in++;
	}
	return (int)out;
}

/* -----------------------------------------------------------------------
 * GDB vFile helpers
 * ---------------------------------------------------------------------- */

static void vfile_put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)(v);
}

static void vfile_put_be64(uint8_t *p, uint64_t v)
{
	vfile_put_be32(p,     (uint32_t)(v >> 32));
	vfile_put_be32(p + 4, (uint32_t)(v));
}

void ela_gdb_vfile_encode_stat(uint8_t *buf, const struct stat *st)
{
	memset(buf, 0, 64);
	vfile_put_be32(buf +  0, (uint32_t)st->st_dev);
	vfile_put_be32(buf +  4, (uint32_t)st->st_ino);
	vfile_put_be32(buf +  8, (uint32_t)st->st_mode);
	vfile_put_be32(buf + 12, (uint32_t)st->st_nlink);
	vfile_put_be32(buf + 16, (uint32_t)st->st_uid);
	vfile_put_be32(buf + 20, (uint32_t)st->st_gid);
	vfile_put_be32(buf + 24, (uint32_t)st->st_rdev);
	vfile_put_be64(buf + 28, (uint64_t)st->st_size);
	vfile_put_be64(buf + 36, (uint64_t)st->st_blksize);
	vfile_put_be64(buf + 44, (uint64_t)st->st_blocks);
	vfile_put_be32(buf + 52, (uint32_t)st->st_atime);
	vfile_put_be32(buf + 56, (uint32_t)st->st_mtime);
	vfile_put_be32(buf + 60, (uint32_t)st->st_ctime);
}

int ela_gdb_vfile_flags_to_linux(int gflags)
{
	int lflags = gflags & 3; /* O_RDONLY/O_WRONLY/O_RDWR values match */
	if (gflags & 0x008) lflags |= O_APPEND;
	if (gflags & 0x200) lflags |= O_CREAT;
	if (gflags & 0x400) lflags |= O_TRUNC;
	if (gflags & 0x800) lflags |= O_EXCL;
	return lflags;
}
