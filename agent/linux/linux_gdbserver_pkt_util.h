// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef LINUX_GDBSERVER_PKT_UTIL_H
#define LINUX_GDBSERVER_PKT_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * Parse an RSP thread-id from the string at s.  Stores the parsed TID in
 * *out_tid and (if the multiprocess "p<pid>.<tid>" form is present) the PID
 * in *out_pid; otherwise *out_pid is set to 0.  Returns the number of input
 * characters consumed, or -1 on parse error.  Either output pointer may be
 * NULL if the caller doesn't need that value.
 */
int ela_gdb_parse_thread_id(const char *s, pid_t *out_pid, pid_t *out_tid);

/*
 * Decode an RSP binary-escape sequence from src into dst.
 * Escape byte 0x7d is followed by the escaped byte XOR'd with 0x20.
 * Reads at most max_src bytes from src; writes exactly expected bytes to dst.
 * Returns expected on success, -1 if src runs out before expected bytes are
 * decoded.
 */
int ela_gdb_rsp_binary_unescape(const char *src, size_t max_src,
				uint8_t *dst, size_t expected);

/*
 * Encode a host struct stat into the 64-byte GDB fio_stat structure.
 * All fields are big-endian.  buf must be at least 64 bytes.
 */
void ela_gdb_vfile_encode_stat(uint8_t *buf, const struct stat *st);

/*
 * Translate GDB fileio open flags to Linux open(2) flags.
 * GDB uses its own constants (from gdb/fileio.h); Linux values differ.
 */
int ela_gdb_vfile_flags_to_linux(int gflags);

/*
 * Convert between Linux signal numbers and GDB RSP signal numbers.
 *
 * GDB uses SVR4-derived signal numbering which matches Linux for signals 1-15
 * but diverges above 15.  Key mappings (Linux → GDB):
 *   Linux 17 (SIGCHLD) → GDB 20
 *   Linux 18 (SIGCONT) → GDB 19
 *   Linux 19 (SIGSTOP) → GDB 17
 *   Linux 20 (SIGTSTP) → GDB 18
 *   Linux 23 (SIGURG)  → GDB 16
 * All other signals pass through unchanged.
 */
int ela_gdb_linux_sig_to_gdb(int linux_sig);
int ela_gdb_gdb_sig_to_linux(int gdb_sig);

#endif /* LINUX_GDBSERVER_PKT_UTIL_H */
