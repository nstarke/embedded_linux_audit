// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef LINUX_PROCESS_WATCH_UTIL_H
#define LINUX_PROCESS_WATCH_UTIL_H

#include <stdbool.h>
#include <stddef.h>

/* Maximum length of a watch needle string (excluding NUL) */
#define ELA_PROCESS_WATCH_NEEDLE_MAX   128

/* Maximum length of a comma-separated PID list string (excluding NUL) */
#define ELA_PROCESS_WATCH_PIDS_MAX_LEN 512

/* Runtime files */
#define ELA_PROCESS_WATCH_STATE_FILE   "/tmp/ela-process-watch.state"
#define ELA_PROCESS_WATCH_PID_FILE     "/tmp/ela-process-watch.pid"
#define ELA_PROCESS_WATCH_LOCK_FILE    "/tmp/ela-process-watch.lock"

/* Seconds between /proc polls */
#define ELA_PROCESS_WATCH_POLL_SECS    2

/*
 * Returns true when needle is a valid watch term:
 *   - non-NULL, non-empty
 *   - at most ELA_PROCESS_WATCH_NEEDLE_MAX bytes
 *   - no newlines or tabs (reserved as state-file delimiters)
 */
bool ela_process_watch_needle_is_valid(const char *needle);

/*
 * Parse one line from the state file: "needle\tpids\n"
 * Writes needle and pids (which may be empty) into the caller-supplied buffers.
 * Returns 0 on success, -1 on any error (bad format, buffer too small, etc.).
 */
int ela_process_watch_state_parse_line(const char *line,
					char *needle_out, size_t needle_sz,
					char *pids_out, size_t pids_sz);

/*
 * Format one state-file line: "needle\tpids\n"
 * Returns 0 on success, -1 if out is NULL or buffer is too small.
 */
int ela_process_watch_state_format_line(const char *needle, const char *pids,
					 char *out, size_t out_sz);

/*
 * Compare two PID strings for equality.  Both are expected to be sorted
 * comma-separated lists of decimal PIDs (the format written by the daemon).
 * NULL is treated as "".
 */
bool ela_process_watch_pids_equal(const char *a, const char *b);

/*
 * Format a process-restart event record into a freshly-malloc'd buffer.
 * fmt must be "txt", "csv", or "json".
 * On success sets *out (caller must free) and *out_len; returns 0.
 * Returns -1 on allocation failure or bad arguments.
 */
int ela_process_watch_format_event(const char *needle,
				    const char *old_pids,
				    const char *new_pids,
				    const char *fmt,
				    char **out,
				    size_t *out_len);

/*
 * Format a watch-list entry (current state for one needle).
 * fmt must be "txt", "csv", or "json".
 * On success sets *out (caller must free) and *out_len; returns 0.
 * Returns -1 on allocation failure or bad arguments.
 */
int ela_process_watch_format_list_entry(const char *needle,
					 const char *pids,
					 const char *fmt,
					 char **out,
					 size_t *out_len);

#endif /* LINUX_PROCESS_WATCH_UTIL_H */
