// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_audit_util.h"

#include "embedded_linux_audit_cmd.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static uint32_t ela_uboot_read_be32_local(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) |
	       ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) |
	       (uint32_t)p[3];
}

bool ela_uboot_str_ieq(const char *a, const char *b)
{
	if (!a || !b)
		return false;
	while (*a && *b) {
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return false;
		a++;
		b++;
	}
	return *a == '\0' && *b == '\0';
}

bool ela_uboot_value_is_enabled(const char *value)
{
	if (!value || !*value)
		return false;
	return ela_uboot_str_ieq(value, "1") ||
	       ela_uboot_str_ieq(value, "y") ||
	       ela_uboot_str_ieq(value, "yes") ||
	       ela_uboot_str_ieq(value, "true") ||
	       ela_uboot_str_ieq(value, "on") ||
	       ela_uboot_str_ieq(value, "enabled");
}

bool ela_uboot_value_is_disabled(const char *value)
{
	if (!value || !*value)
		return true;
	return ela_uboot_str_ieq(value, "0") ||
	       ela_uboot_str_ieq(value, "n") ||
	       ela_uboot_str_ieq(value, "no") ||
	       ela_uboot_str_ieq(value, "false") ||
	       ela_uboot_str_ieq(value, "off") ||
	       ela_uboot_str_ieq(value, "disabled");
}

bool ela_uboot_value_is_nonempty(const char *value)
{
	return value && *value;
}

static int hex_nibble(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int ela_uboot_decode_hex_signature(const char *sig, uint8_t **out, size_t *out_len)
{
	char *clean = NULL;
	size_t slen;
	size_t cpos = 0;
	uint8_t *buf = NULL;
	size_t blen;
	size_t i;

	if (!sig || !*sig || !out || !out_len)
		return -1;
	if (!strncmp(sig, "0x", 2) || !strncmp(sig, "0X", 2))
		sig += 2;

	slen = strlen(sig);
	clean = malloc(slen + 1);
	if (!clean)
		return -1;

	for (i = 0; i < slen; i++) {
		if (isxdigit((unsigned char)sig[i])) {
			clean[cpos++] = sig[i];
			continue;
		}
		if (sig[i] == ':' || sig[i] == '-' || isspace((unsigned char)sig[i]))
			continue;
		free(clean);
		return -1;
	}

	if (!cpos || (cpos % 2) != 0) {
		free(clean);
		return -1;
	}

	blen = cpos / 2;
	buf = malloc(blen);
	if (!buf) {
		free(clean);
		return -1;
	}

	for (i = 0; i < blen; i++) {
		int hi = hex_nibble(clean[i * 2]);
		int lo = hex_nibble(clean[i * 2 + 1]);
		if (hi < 0 || lo < 0) {
			free(clean);
			free(buf);
			return -1;
		}
		buf[i] = (uint8_t)((hi << 4) | lo);
	}

	free(clean);
	*out = buf;
	*out_len = blen;
	return 0;
}

static int base64_value(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

int ela_uboot_decode_base64_signature(const char *sig, uint8_t **out, size_t *out_len)
{
	char *clean = NULL;
	size_t slen;
	size_t cpos = 0;
	size_t i;
	size_t produced = 0;
	uint8_t *buf = NULL;

	if (!sig || !*sig || !out || !out_len)
		return -1;

	slen = strlen(sig);
	clean = malloc(slen + 1);
	if (!clean)
		return -1;

	for (i = 0; i < slen; i++) {
		if (!isspace((unsigned char)sig[i]))
			clean[cpos++] = sig[i];
	}
	clean[cpos] = '\0';

	if (!cpos || (cpos % 4) != 0) {
		free(clean);
		return -1;
	}

	buf = malloc((cpos / 4) * 3);
	if (!buf) {
		free(clean);
		return -1;
	}

	for (i = 0; i < cpos; i += 4) {
		int a = base64_value(clean[i]);
		int b = base64_value(clean[i + 1]);
		int c = clean[i + 2] == '=' ? -2 : base64_value(clean[i + 2]);
		int d = clean[i + 3] == '=' ? -2 : base64_value(clean[i + 3]);

		if (a < 0 || b < 0 || c == -1 || d == -1) {
			free(clean);
			free(buf);
			return -1;
		}

		buf[produced++] = (uint8_t)((a << 2) | (b >> 4));
		if (c != -2) {
			buf[produced++] = (uint8_t)(((b & 0x0F) << 4) | (c >> 2));
			if (d != -2)
				buf[produced++] = (uint8_t)(((c & 0x03) << 6) | d);
		}
	}

	free(clean);
	*out = buf;
	*out_len = produced;
	return 0;
}

int ela_uboot_decode_signature_value(const char *sig, uint8_t **out, size_t *out_len)
{
	if (ela_uboot_decode_hex_signature(sig, out, out_len) == 0)
		return 0;
	return ela_uboot_decode_base64_signature(sig, out, out_len);
}

int ela_uboot_parse_env_pairs(const uint8_t *buf, size_t len, size_t data_off,
			      struct env_kv_view *pairs, size_t max_pairs)
{
	size_t off = data_off;
	size_t count = 0;

	if (!buf || data_off >= len || !pairs || !max_pairs)
		return -1;

	while (off < len && count < max_pairs) {
		const char *entry;
		size_t slen;
		const char *eq;

		if (buf[off] == '\0') {
			if (off + 1 >= len || buf[off + 1] == '\0')
				break;
			off++;
			continue;
		}

		entry = (const char *)(buf + off);
		slen = strnlen(entry, len - off);
		if (slen >= len - off)
			break;

		eq = memchr(entry, '=', slen);
		if (eq) {
			pairs[count].name = entry;
			pairs[count].value = eq + 1;
			count++;
		}
		off += slen + 1;
	}

	return (int)count;
}

const char *ela_uboot_find_env_value(const struct env_kv_view *pairs, size_t count, const char *name)
{
	size_t i;

	for (i = 0; i < count; i++) {
		size_t nlen;

		if (!pairs[i].name || !pairs[i].value)
			continue;
		nlen = strcspn(pairs[i].name, "=");
		if (strlen(name) == nlen && !strncmp(pairs[i].name, name, nlen))
			return pairs[i].value;
	}
	return NULL;
}

int ela_uboot_choose_env_data_offset(const struct embedded_linux_audit_input *input, size_t *data_off)
{
	uint32_t stored_le;
	uint32_t stored_be;
	uint32_t calc_std;
	uint32_t calc_redund;

	if (!input || !data_off || !input->data || !input->crc32_table || input->data_len < 8)
		return -1;

	stored_le = (uint32_t)input->data[0] |
		((uint32_t)input->data[1] << 8) |
		((uint32_t)input->data[2] << 16) |
		((uint32_t)input->data[3] << 24);
	stored_be = ela_uboot_read_be32_local(input->data);

	calc_std = ela_crc32_calc(input->crc32_table, input->data + 4, input->data_len - 4);
	if (calc_std == stored_le || calc_std == stored_be) {
		*data_off = 4;
		return 0;
	}

	if (input->data_len <= 5)
		return -1;

	calc_redund = ela_crc32_calc(input->crc32_table, input->data + 5, input->data_len - 5);
	if (calc_redund == stored_le || calc_redund == stored_be) {
		*data_off = 5;
		return 0;
	}

	return -1;
}

int ela_uboot_parse_int_value(const char *s, int *out)
{
	long v = 0;
	int sign = 1;

	if (!s || !*s || !out)
		return -1;
	if (*s == '+')
		s++;
	else if (*s == '-') {
		s++;
		sign = -1;
	}
	if (!*s)
		return -1;

	for (; *s; s++) {
		if (!isdigit((unsigned char)*s))
			return -1;
		v = (v * 10) + (*s - '0');
		if (v > 2147483647L)
			return -1;
	}

	*out = (int)(v * sign);
	return 0;
}

bool ela_uboot_contains_token_ci(const char *s, const char *token)
{
	size_t tlen;
	const char *p;

	if (!s || !*s || !token || !*token)
		return false;
	tlen = strlen(token);
	for (p = s; *p; p++) {
		size_t i;
		for (i = 0; i < tlen; i++) {
			if (!p[i])
				return false;
			if (tolower((unsigned char)p[i]) != tolower((unsigned char)token[i]))
				break;
		}
		if (i == tlen)
			return true;
	}
	return false;
}

bool ela_uboot_value_suggests_network_boot(const char *value)
{
	static const char *network_tokens[] = {
		"dhcp", "pxe", "tftp", "bootp", "nfs", "netboot", "httpboot",
	};
	size_t i;

	if (!value || !*value)
		return false;
	for (i = 0; i < sizeof(network_tokens) / sizeof(network_tokens[0]); i++) {
		if (ela_uboot_contains_token_ci(value, network_tokens[i]))
			return true;
	}
	return false;
}

bool ela_uboot_value_suggests_factory_reset(const char *value)
{
	static const char *factory_reset_tokens[] = {
		"factory_reset", "factory reset", "reset_to_defaults", "restore_defaults",
		"resetenv", "eraseenv", "env default -a", "default -f -a", "wipe_data",
	};
	size_t i;

	if (!value || !*value)
		return false;
	for (i = 0; i < sizeof(factory_reset_tokens) / sizeof(factory_reset_tokens[0]); i++) {
		if (ela_uboot_contains_token_ci(value, factory_reset_tokens[i]))
			return true;
	}
	return false;
}

bool ela_uboot_init_path_looks_valid(const char *v)
{
	const unsigned char *p;

	if (!v || !*v || *v != '/')
		return false;
	for (p = (const unsigned char *)v; *p; p++) {
		if (isspace(*p) || iscntrl(*p) || *p == '"' || *p == '\'')
			return false;
	}
	return true;
}

bool ela_uboot_parse_init_parameter(const char *cmdline, char *init_value, size_t init_value_len)
{
	const char *p = cmdline;

	if (!cmdline || !*cmdline || !init_value || init_value_len == 0)
		return false;

	while (*p) {
		const char *tok_start;
		size_t tok_len;

		while (*p && isspace((unsigned char)*p))
			p++;
		if (!*p)
			break;

		tok_start = p;
		while (*p && !isspace((unsigned char)*p))
			p++;
		tok_len = (size_t)(p - tok_start);

		if (tok_len > 5 && !strncmp(tok_start, "init=", 5)) {
			size_t val_len = tok_len - 5;
			if (val_len >= init_value_len)
				val_len = init_value_len - 1;
			memcpy(init_value, tok_start + 5, val_len);
			init_value[val_len] = '\0';
			return true;
		}
	}

	return false;
}
