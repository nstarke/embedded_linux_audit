// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_security_audit_util.h"
#include "util/str_util.h"
#include "image/uboot_image_scan_util.h"

#include <stdlib.h>
#include <string.h>

int ela_uboot_audit_http_buf_append(char **buf, size_t *len, size_t *cap,
				    const char *data, size_t data_len)
{
	if (!data || !data_len)
		return -1;
	return append_bytes(buf, len, cap, data, data_len);
}

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
	return ela_uboot_detect_output_format(fmt);
}

bool ela_uboot_fit_header_looks_valid(const uint8_t *p, uint64_t abs_off, uint64_t dev_size)
{
	return ela_uboot_image_validate_fit_header(p, abs_off, dev_size);
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
