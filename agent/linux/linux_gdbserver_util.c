// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_gdbserver_util.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

uint8_t ela_gdb_rsp_checksum(const char *data, size_t len)
{
	uint8_t sum = 0;
	size_t i;

	if (!data)
		return 0;
	for (i = 0; i < len; i++)
		sum += (uint8_t)data[i];
	return sum;
}

int ela_gdb_rsp_frame(const char *data, size_t data_len,
		      char *out, size_t out_sz)
{
	uint8_t cksum;

	if (!out || out_sz < data_len + 5)
		return -1;

	cksum = ela_gdb_rsp_checksum(data, data_len);
	out[0] = '$';
	if (data && data_len > 0)
		memcpy(out + 1, data, data_len);
	snprintf(out + 1 + data_len, 4, "#%02x", cksum);
	return 0;
}

int ela_gdb_rsp_unframe(const char *pkt, size_t pkt_len,
			char *data_out, size_t data_sz)
{
	const char *hash;
	size_t data_len;
	uint8_t expected, actual;
	unsigned int ck_hi = 0, ck_lo = 0;

	if (!pkt || pkt_len < 4)
		return -1;
	if (pkt[0] != '$')
		return -1;

	hash = memchr(pkt + 1, '#', pkt_len - 1);
	if (!hash || (size_t)(hash - pkt) + 2 >= pkt_len)
		return -1;

	data_len = (size_t)(hash - pkt - 1);

	if (!isxdigit((unsigned char)hash[1]) ||
	    !isxdigit((unsigned char)hash[2]))
		return -1;

	sscanf(hash + 1, "%1x%1x", &ck_hi, &ck_lo);
	expected = (uint8_t)((ck_hi << 4) | ck_lo);

	actual = ela_gdb_rsp_checksum(pkt + 1, data_len);
	if (actual != expected)
		return -1;

	if (!data_out || data_sz < data_len + 1)
		return -1;

	memcpy(data_out, pkt + 1, data_len);
	data_out[data_len] = '\0';
	return (int)data_len;
}

int ela_gdb_hex_encode(const uint8_t *src, size_t src_len,
		       char *out, size_t out_sz)
{
	static const char hex_chars[] = "0123456789abcdef";
	size_t i;

	if (!out || out_sz < 2 * src_len + 1)
		return -1;

	if (!src || src_len == 0) {
		out[0] = '\0';
		return 0;
	}

	for (i = 0; i < src_len; i++) {
		out[2 * i]     = hex_chars[src[i] >> 4];
		out[2 * i + 1] = hex_chars[src[i] & 0x0f];
	}
	out[2 * src_len] = '\0';
	return 0;
}

static int hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int ela_gdb_hex_decode(const char *hex, uint8_t *out, size_t out_sz)
{
	size_t len;
	size_t i;
	int hi, lo;

	if (!hex)
		return -1;

	len = strlen(hex);
	if (len % 2 != 0)
		return -1;
	if (len == 0)
		return 0;

	if (!out || out_sz < len / 2)
		return -1;

	for (i = 0; i < len; i += 2) {
		hi = hex_val(hex[i]);
		lo = hex_val(hex[i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		out[i / 2] = (uint8_t)((hi << 4) | lo);
	}
	return (int)(len / 2);
}

char ela_gdb_rsp_ack(bool ok)
{
	return ok ? '+' : '-';
}

int ela_gdb_encode_le64(uint64_t val, char *out, size_t out_sz)
{
	uint8_t bytes[8];
	int i;

	if (!out || out_sz < 17)
		return -1;

	for (i = 0; i < 8; i++)
		bytes[i] = (uint8_t)(val >> (8 * i));

	return ela_gdb_hex_encode(bytes, 8, out, out_sz);
}

int ela_gdb_encode_le32(uint32_t val, char *out, size_t out_sz)
{
	uint8_t bytes[4];
	int i;

	if (!out || out_sz < 9)
		return -1;

	for (i = 0; i < 4; i++)
		bytes[i] = (uint8_t)(val >> (8 * i));

	return ela_gdb_hex_encode(bytes, 4, out, out_sz);
}

int ela_gdb_encode_be64(uint64_t val, char *out, size_t out_sz)
{
	uint8_t bytes[8];
	int i;

	if (!out || out_sz < 17)
		return -1;

	for (i = 0; i < 8; i++)
		bytes[i] = (uint8_t)(val >> (8 * (7 - i)));

	return ela_gdb_hex_encode(bytes, 8, out, out_sz);
}

int ela_gdb_encode_be32(uint32_t val, char *out, size_t out_sz)
{
	uint8_t bytes[4];
	int i;

	if (!out || out_sz < 9)
		return -1;

	for (i = 0; i < 4; i++)
		bytes[i] = (uint8_t)(val >> (8 * (3 - i)));

	return ela_gdb_hex_encode(bytes, 4, out, out_sz);
}

int ela_gdb_decode_le32(const char *hex, uint32_t *out)
{
	uint8_t bytes[4];
	int i;

	if (!hex || !out)
		return -1;
	if (ela_gdb_hex_decode(hex, bytes, sizeof(bytes)) != 4)
		return -1;
	*out = 0;
	for (i = 0; i < 4; i++)
		*out |= (uint32_t)bytes[i] << (8 * i);
	return 0;
}

int ela_gdb_decode_le64(const char *hex, uint64_t *out)
{
	uint8_t bytes[8];
	int i;

	if (!hex || !out)
		return -1;
	if (ela_gdb_hex_decode(hex, bytes, sizeof(bytes)) != 8)
		return -1;
	*out = 0;
	for (i = 0; i < 8; i++)
		*out |= (uint64_t)bytes[i] << (8 * i);
	return 0;
}

int ela_gdb_decode_be32(const char *hex, uint32_t *out)
{
	uint8_t bytes[4];
	int i;

	if (!hex || !out)
		return -1;
	if (ela_gdb_hex_decode(hex, bytes, sizeof(bytes)) != 4)
		return -1;
	*out = 0;
	for (i = 0; i < 4; i++)
		*out |= (uint32_t)bytes[i] << (8 * (3 - i));
	return 0;
}

int ela_gdb_decode_be64(const char *hex, uint64_t *out)
{
	uint8_t bytes[8];
	int i;

	if (!hex || !out)
		return -1;
	if (ela_gdb_hex_decode(hex, bytes, sizeof(bytes)) != 8)
		return -1;
	*out = 0;
	for (i = 0; i < 8; i++)
		*out |= (uint64_t)bytes[i] << (8 * (7 - i));
	return 0;
}

int ela_gdb_parse_hex_u64(const char *hex, uint64_t *out)
{
	char *endptr;
	unsigned long long val;

	if (!hex || !out || hex[0] == '\0')
		return -1;

	val = strtoull(hex, &endptr, 16);
	if (endptr == hex || *endptr != '\0')
		return -1;

	*out = (uint64_t)val;
	return 0;
}

int ela_gdb_svr4_path_skip(const char *path)
{
	if (!path)
		return 1;
	if (path[0] == '[')
		return 1;
	if (!strstr(path, ".so"))
		return 1;
	if (strstr(path, " (deleted)"))
		return 1;
	return 0;
}
