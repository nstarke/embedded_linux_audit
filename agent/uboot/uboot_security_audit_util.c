// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_security_audit_util.h"

#include <stdlib.h>
#include <string.h>

int ela_uboot_audit_http_buf_append(char **buf, size_t *len, size_t *cap,
				    const char *data, size_t data_len)
{
	size_t need;
	size_t new_cap;
	char *tmp;

	if (!buf || !len || !cap || !data || !data_len)
		return -1;

	need = *len + data_len + 1;
	if (need > *cap) {
		new_cap = *cap ? *cap : 1024;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(*buf, new_cap);
		if (!tmp)
			return -1;
		*buf = tmp;
		*cap = new_cap;
	}

	memcpy(*buf + *len, data, data_len);
	*len += data_len;
	(*buf)[*len] = '\0';
	return 0;
}

#define FIT_MIN_TOTAL_SIZE 0x100U
#define FIT_MAX_TOTAL_SIZE (64U * 1024U * 1024U)

uint32_t ela_uboot_read_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) |
	       ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) |
	       (uint32_t)p[3];
}

static const char *find_bytes(const char *buf, size_t len, const char *needle, size_t needle_len)
{
	size_t off;

	if (!buf || !needle || needle_len == 0 || needle_len > len)
		return NULL;

	for (off = 0; off + needle_len <= len; off++) {
		if (!memcmp(buf + off, needle, needle_len))
			return buf + off;
	}

	return NULL;
}

bool ela_uboot_buffer_has_newline(const char *buf, size_t len)
{
	if (!buf || !len)
		return false;
	return memchr(buf, '\n', len) != NULL;
}

bool ela_uboot_audit_rule_may_need_signature_artifacts(const char *rule_filter)
{
	if (!rule_filter || !*rule_filter)
		return true;
	return !strcmp(rule_filter, "uboot_validate_secureboot");
}

enum uboot_output_format ela_uboot_audit_detect_output_format(const char *fmt)
{
	if (!fmt || !*fmt || !strcmp(fmt, "txt"))
		return FW_OUTPUT_TXT;
	if (!strcmp(fmt, "csv"))
		return FW_OUTPUT_CSV;
	if (!strcmp(fmt, "json"))
		return FW_OUTPUT_JSON;
	return FW_OUTPUT_TXT;
}

bool ela_uboot_fit_header_looks_valid(const uint8_t *p, uint64_t abs_off, uint64_t dev_size)
{
	uint32_t totalsize = ela_uboot_read_be32(p + 4);
	uint32_t off_dt_struct = ela_uboot_read_be32(p + 8);
	uint32_t off_dt_strings = ela_uboot_read_be32(p + 12);
	uint32_t off_mem_rsvmap = ela_uboot_read_be32(p + 16);
	uint32_t version = ela_uboot_read_be32(p + 20);
	uint32_t last_comp_version = ela_uboot_read_be32(p + 24);
	uint32_t size_dt_strings = ela_uboot_read_be32(p + 32);
	uint32_t size_dt_struct = ela_uboot_read_be32(p + 36);

	if (totalsize < FIT_MIN_TOTAL_SIZE || totalsize > FIT_MAX_TOTAL_SIZE)
		return false;
	if (abs_off + totalsize > dev_size)
		return false;
	if (off_mem_rsvmap < 40 || off_mem_rsvmap >= totalsize)
		return false;
	if (off_dt_struct >= totalsize || off_dt_strings >= totalsize)
		return false;
	if (size_dt_struct == 0 || size_dt_strings == 0)
		return false;
	if ((uint64_t)off_dt_struct + size_dt_struct > totalsize)
		return false;
	if ((uint64_t)off_dt_strings + size_dt_strings > totalsize)
		return false;
	if (version < 16 || version > 17)
		return false;
	if (last_comp_version > version)
		return false;
	return true;
}

int ela_uboot_extract_public_key_pem(const char *text, size_t len, char **pem_out)
{
	static const char begin_marker[] = "-----BEGIN PUBLIC KEY-----";
	static const char end_marker[] = "-----END PUBLIC KEY-----";
	const char *begin;
	const char *end;
	size_t pem_len;
	char *pem;

	if (!text || !pem_out)
		return -1;

	begin = find_bytes(text, len, begin_marker, sizeof(begin_marker) - 1);
	if (!begin)
		return -1;

	end = find_bytes(begin, len - (size_t)(begin - text), end_marker, sizeof(end_marker) - 1);
	if (!end)
		return -1;

	pem_len = (size_t)(end - begin) + sizeof(end_marker) - 1;
	pem = malloc(pem_len + 2);
	if (!pem)
		return -1;

	memcpy(pem, begin, pem_len);
	if (pem_len == 0 || pem[pem_len - 1] != '\n') // cppcheck-suppress knownConditionTrueFalse
		pem[pem_len++] = '\n';
	pem[pem_len] = '\0';
	*pem_out = pem;
	return 0;
}
