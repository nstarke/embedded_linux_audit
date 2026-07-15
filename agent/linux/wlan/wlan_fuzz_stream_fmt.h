// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Pure formatter for the remote crash-capture stream (wext-generic mode).
 * Kept free of any socket/TLS dependency so it is unit-testable without a
 * network. Produces the same one-line-per-case form the on-disk crash files
 * use ("<MSGNAME> <hexpayload> #<note>"), so what the API saves on an
 * ungraceful disconnect is directly replayable with `wlan fuzz --replay`.
 */
#ifndef WLAN_FUZZ_STREAM_FMT_H
#define WLAN_FUZZ_STREAM_FMT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Render one fuzz case into `out` as "<msg_name> <hex> #<note>" (note omitted
 * when empty). Returns the string length written (>= 0), or -1 if any argument
 * is invalid or the buffer is too small for even the header. The payload is
 * truncated to whatever fits; callers size `out` for CASE_MAX_BYTES*2 + slack.
 */
int wlan_fuzz_format_case_line(char *out, size_t outsz, const char *msg_name,
			       const uint8_t *payload, int len, const char *note);

#endif
