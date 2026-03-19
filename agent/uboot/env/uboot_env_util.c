// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_env_util.h"

#include "embedded_linux_audit_cmd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t ela_uboot_read_be32_local(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) |
	       ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) |
	       (uint32_t)p[3];
}

void ela_uboot_env_free_kvs(struct env_kv *kvs, size_t count)
{
	size_t i;

	if (!kvs)
		return;
	for (i = 0; i < count; i++) {
		free(kvs[i].name);
		free(kvs[i].value);
	}
	free(kvs);
}

int ela_uboot_env_set_kv(struct env_kv **kvs, size_t *count, const char *name, const char *value)
{
	struct env_kv *tmp;
	char *name_dup;
	char *value_dup;
	size_t i;

	if (!kvs || !count || !name || !value)
		return -1;

	for (i = 0; i < *count; i++) {
		if (strcmp((*kvs)[i].name, name))
			continue;
		value_dup = strdup(value);
		if (!value_dup)
			return -1;
		free((*kvs)[i].value);
		(*kvs)[i].value = value_dup;
		return 0;
	}

	tmp = realloc(*kvs, (*count + 1) * sizeof(**kvs));
	if (!tmp)
		return -1;
	*kvs = tmp;

	name_dup = strdup(name);
	value_dup = strdup(value);
	if (!name_dup || !value_dup) {
		free(name_dup);
		free(value_dup);
		return -1;
	}

	(*kvs)[*count].name = name_dup;
	(*kvs)[*count].value = value_dup;
	(*count)++;
	return 0;
}

int ela_uboot_env_unset_kv(struct env_kv *kvs, size_t *count, const char *name)
{
	size_t i;
	size_t j;

	if (!kvs || !count || !name)
		return -1;

	for (i = 0; i < *count; i++) {
		if (strcmp(kvs[i].name, name))
			continue;
		free(kvs[i].name);
		free(kvs[i].value);
		for (j = i + 1; j < *count; j++)
			kvs[j - 1] = kvs[j];
		(*count)--;
		return 0;
	}

	return 0;
}

int ela_uboot_parse_fw_config_line(const char *line, struct uboot_cfg_entry *out)
{
	char dev[256];
	char off_s[64];
	char size_s[64];
	char erase_s[64];
	char sec_s[64];
	uint64_t off;
	uint64_t env_size;
	uint64_t erase;
	uint64_t sec;

	if (!line || !out)
		return -1;
	while (*line == ' ' || *line == '\t')
		line++;
	if (!*line || *line == '#')
		return 0;

	if (sscanf(line, "%255s %63s %63s %63s %63s", dev, off_s, size_s, erase_s, sec_s) != 5)
		return -1;
	if (ela_parse_u64(off_s, &off) || ela_parse_u64(size_s, &env_size) ||
	    ela_parse_u64(erase_s, &erase) || ela_parse_u64(sec_s, &sec))
		return -1;
	if (!env_size || env_size < 8)
		return -1;

	strncpy(out->dev, dev, sizeof(out->dev) - 1);
	out->dev[sizeof(out->dev) - 1] = '\0';
	out->off = off;
	out->env_size = env_size;
	out->erase_size = erase;
	out->sectors = sec;
	return 1;
}

int ela_uboot_parse_existing_env_data(const uint8_t *buf, size_t buf_len, size_t data_off,
				      struct env_kv **kvs, size_t *count)
{
	size_t off = data_off;

	if (!buf || !kvs || !count || data_off >= buf_len)
		return -1;

	while (off < buf_len) {
		const char *entry;
		size_t slen;
		const char *eq;
		char *name;
		char *value;

		if (buf[off] == '\0') {
			if (off + 1 >= buf_len || buf[off + 1] == '\0')
				break;
			off++;
			continue;
		}

		entry = (const char *)(buf + off);
		slen = strnlen(entry, buf_len - off);
		if (slen >= buf_len - off)
			break;

		eq = memchr(entry, '=', slen);
		if (!eq) {
			off += slen + 1;
			continue;
		}

		name = strndup(entry, (size_t)(eq - entry));
		value = strndup(eq + 1, slen - (size_t)(eq - entry) - 1);
		if (!name || !value || ela_uboot_env_set_kv(kvs, count, name, value) != 0) {
			free(name);
			free(value);
			return -1;
		}
		free(name);
		free(value);
		off += slen + 1;
	}

	return 0;
}

int ela_uboot_build_env_region(const struct env_kv *kvs, size_t count, uint8_t *out, size_t out_len)
{
	size_t i;
	size_t pos = 0;

	if (!out || out_len < 2)
		return -1;

	memset(out, 0, out_len);
	for (i = 0; i < count; i++) {
		size_t nlen = strlen(kvs[i].name);
		size_t vlen = strlen(kvs[i].value);
		size_t need = nlen + 1 + vlen + 1;

		if (pos + need + 1 > out_len)
			return -1;

		memcpy(out + pos, kvs[i].name, nlen);
		pos += nlen;
		out[pos++] = '=';
		memcpy(out + pos, kvs[i].value, vlen);
		pos += vlen;
		out[pos++] = '\0';
	}

	if (pos + 1 > out_len)
		return -1;
	out[pos++] = '\0';
	return 0;
}

bool ela_uboot_env_crc_matches(const uint32_t *crc32_table,
			       const uint8_t *buf,
			       size_t env_size,
			       size_t data_off,
			       bool *is_le)
{
	uint32_t stored_le;
	uint32_t stored_be;
	uint32_t calc;

	if (!crc32_table || !buf || env_size <= data_off || !is_le)
		return false;

	stored_le = (uint32_t)buf[0] |
		((uint32_t)buf[1] << 8) |
		((uint32_t)buf[2] << 16) |
		((uint32_t)buf[3] << 24);
	stored_be = ela_uboot_read_be32_local(buf);
	calc = ela_crc32_calc(crc32_table, buf + data_off, env_size - data_off);
	if (calc == stored_le) {
		*is_le = true;
		return true;
	}
	if (calc == stored_be) {
		*is_le = false;
		return true;
	}
	return false;
}
