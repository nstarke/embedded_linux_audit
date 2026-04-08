// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef LINUX_GDBSERVER_UTIL_H
#define LINUX_GDBSERVER_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Maximum payload size of an RSP packet (not including $ and #xx wrapper) */
#define ELA_GDB_RSP_MAX_PACKET  4096

/* Maximum framed packet size: $ + data + # + xx + NUL */
#define ELA_GDB_RSP_MAX_FRAMED  (ELA_GDB_RSP_MAX_PACKET + 5)

/*
 * Compute the RSP checksum: sum of all bytes in data[] mod 256.
 * Returns 0 for NULL or empty input.
 */
uint8_t ela_gdb_rsp_checksum(const char *data, size_t len);

/*
 * Frame `data_len` bytes from `data` as an RSP packet "$data#xx\0".
 * `out` must be at least data_len + 5 bytes.
 * Returns 0 on success, -1 if out is NULL or out_sz is too small.
 */
int ela_gdb_rsp_frame(const char *data, size_t data_len,
		      char *out, size_t out_sz);

/*
 * Validate and unframe an RSP packet of the form "$...<data>...#xx".
 * Verifies the two-hex-digit checksum.  Copies the payload (NUL-terminated)
 * into data_out.
 * Returns the payload length on success, -1 on any error.
 */
int ela_gdb_rsp_unframe(const char *pkt, size_t pkt_len,
			char *data_out, size_t data_sz);

/*
 * Hex-encode `src_len` bytes from `src` into `out` (lowercase).
 * `out` must be >= 2*src_len + 1 bytes.
 * Returns 0 on success, -1 if out is NULL or out_sz is too small.
 * src may be NULL only when src_len == 0.
 */
int ela_gdb_hex_encode(const uint8_t *src, size_t src_len,
		       char *out, size_t out_sz);

/*
 * Hex-decode the NUL-terminated string `hex` into `out`.
 * Returns the number of bytes written, or -1 on bad input, odd-length
 * string, or buffer too small.
 */
int ela_gdb_hex_decode(const char *hex, uint8_t *out, size_t out_sz);

/*
 * Return '+' if ok is true, '-' otherwise.
 */
char ela_gdb_rsp_ack(bool ok);

/*
 * Encode a 64-bit value in little-endian byte order as 16 lowercase hex
 * chars (the format GDB uses for 64-bit registers).
 * `out` must be >= 17 bytes.
 * Returns 0 on success, -1 if out is NULL or out_sz < 17.
 */
int ela_gdb_encode_le64(uint64_t val, char *out, size_t out_sz);

/*
 * Encode a 32-bit value in little-endian byte order as 8 lowercase hex
 * chars (the format GDB uses for 32-bit registers).
 * `out` must be >= 9 bytes.
 * Returns 0 on success, -1 if out is NULL or out_sz < 9.
 */
int ela_gdb_encode_le32(uint32_t val, char *out, size_t out_sz);

/*
 * Encode a 64-bit value in big-endian byte order as 16 lowercase hex chars
 * (the format GDB uses for 64-bit registers on big-endian targets).
 * `out` must be >= 17 bytes.
 * Returns 0 on success, -1 if out is NULL or out_sz < 17.
 */
int ela_gdb_encode_be64(uint64_t val, char *out, size_t out_sz);

/*
 * Encode a 32-bit value in big-endian byte order as 8 lowercase hex chars
 * (the format GDB uses for 32-bit registers on big-endian targets).
 * `out` must be >= 9 bytes.
 * Returns 0 on success, -1 if out is NULL or out_sz < 9.
 */
int ela_gdb_encode_be32(uint32_t val, char *out, size_t out_sz);

/*
 * Decode a GDB register hex string (as produced by ela_gdb_encode_le32) back
 * to a uint32_t.  Expects exactly 8 lowercase or uppercase hex chars.
 * Returns 0 on success, -1 on NULL, wrong length, or bad input.
 */
int ela_gdb_decode_le32(const char *hex, uint32_t *out);

/*
 * Decode a GDB register hex string (as produced by ela_gdb_encode_le64) back
 * to a uint64_t.  Expects exactly 16 hex chars.
 * Returns 0 on success, -1 on NULL, wrong length, or bad input.
 */
int ela_gdb_decode_le64(const char *hex, uint64_t *out);

/*
 * Decode a GDB register hex string (as produced by ela_gdb_encode_be32) back
 * to a uint32_t.  Expects exactly 8 hex chars.
 * Returns 0 on success, -1 on NULL, wrong length, or bad input.
 */
int ela_gdb_decode_be32(const char *hex, uint32_t *out);

/*
 * Decode a GDB register hex string (as produced by ela_gdb_encode_be64) back
 * to a uint64_t.  Expects exactly 16 hex chars.
 * Returns 0 on success, -1 on NULL, wrong length, or bad input.
 */
int ela_gdb_decode_be64(const char *hex, uint64_t *out);

/*
 * Parse a hex string (no "0x" prefix, no leading sign) as a uint64_t.
 * Returns 0 on success, -1 on NULL/empty/bad input.
 */
int ela_gdb_parse_hex_u64(const char *hex, uint64_t *out);

/*
 * Return 1 if path should be excluded from the SVR4 library list sent to GDB,
 * 0 if it should be included.
 *
 * Excluded paths:
 *  - anonymous/pseudo mappings that start with '[' (e.g. "[heap]", "[stack]")
 *  - mappings that do not contain ".so" (not a shared library)
 *  - mappings with " (deleted)" suffix (file has been removed; GDB cannot open
 *    it via vFile and will report an I/O error instead)
 */
int ela_gdb_svr4_path_skip(const char *path);

#endif /* LINUX_GDBSERVER_UTIL_H */
