// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_command_extract_util.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static bool token_in_list_ci(const char *token, const char *const *list, size_t list_count)
{
	size_t i;

	for (i = 0; i < list_count; i++) {
		if (!strcasecmp(token, list[i]))
			return true;
	}
	return false;
}

static bool bytes_contains_token_ci(const uint8_t *buf, size_t len, const char *needle)
{
	size_t i;
	size_t nlen;

	if (!buf || !needle)
		return false;

	nlen = strlen(needle);
	if (!nlen || len < nlen)
		return false;

	for (i = 0; i + nlen <= len; i++) {
		size_t j = 0;
		for (; j < nlen; j++) {
			if (tolower((unsigned char)buf[i + j]) != tolower((unsigned char)needle[j]))
				break;
		}
		if (j == nlen)
			return true;
	}
	return false;
}

static bool token_has_command_context(const uint8_t *buf, size_t len, size_t start, size_t end)
{
	static const char *const ctx_needles[] = {
		"unknown command",
		"list of commands",
		"commands",
		"usage:",
		"help",
		"cmd"
	};
	size_t i;
	size_t lo = (start > 96U) ? (start - 96U) : 0U;
	size_t hi = end + 96U;

	if (hi > len)
		hi = len;
	if (hi <= lo)
		return false;

	for (i = 0; i < ARRAY_SIZE(ctx_needles); i++) {
		if (bytes_contains_token_ci(buf + lo, hi - lo, ctx_needles[i]))
			return true;
	}
	return false;
}

bool ela_uboot_is_printable_ascii(uint8_t c)
{
	return c >= 0x20 && c <= 0x7e;
}

bool ela_uboot_token_looks_like_command_name(const char *s)
{
	size_t i;
	size_t len;
	bool has_alpha = false;

	if (!s)
		return false;

	len = strlen(s);
	if (len < 2 || len > 32)
		return false;

	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];

		if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
			return false;
		if (isalpha(c))
			has_alpha = true;
	}

	return has_alpha && isalpha((unsigned char)s[0]);
}

static int find_extracted_command(struct extracted_command *cmds, size_t count, const char *name)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (!strcmp(cmds[i].name, name))
			return (int)i;
	}
	return -1;
}

static int add_extracted_command(struct extracted_command **cmds,
				 size_t *count,
				 const char *name,
				 int occ_score,
				 bool known,
				 bool context_seen)
{
	int idx = find_extracted_command(*cmds, *count, name);
	struct extracted_command *tmp;

	if (idx >= 0) {
		struct extracted_command *c = &(*cmds)[(size_t)idx];
		c->hits++;
		if (occ_score > c->best_occ_score)
			c->best_occ_score = occ_score;
		if (known)
			c->known = true;
		if (context_seen)
			c->context_seen = true;
		return 0;
	}

	tmp = realloc(*cmds, (*count + 1U) * sizeof(**cmds));
	if (!tmp)
		return -1;
	*cmds = tmp;

	tmp[*count].name = strdup(name);
	if (!tmp[*count].name)
		return -1;
	tmp[*count].hits = 1;
	tmp[*count].best_occ_score = occ_score;
	tmp[*count].known = known;
	tmp[*count].context_seen = context_seen;
	(*count)++;
	return 0;
}

int ela_uboot_extracted_command_final_score(const struct extracted_command *c)
{
	int score;
	unsigned int extra;

	if (!c)
		return 0;

	score = c->best_occ_score;
	if (c->known)
		score += 2;
	if (c->context_seen)
		score += 1;
	if (c->hits > 1) {
		extra = c->hits - 1;
		if (extra > 3)
			extra = 3;
		score += (int)extra;
	}

	return score;
}

const char *ela_uboot_confidence_from_score(int score)
{
	if (score >= 10)
		return "high";
	if (score >= 7)
		return "medium";
	return "low";
}

static int extracted_command_cmp(const void *a, const void *b)
{
	const struct extracted_command *ca = (const struct extracted_command *)a;
	const struct extracted_command *cb = (const struct extracted_command *)b;
	int sa = ela_uboot_extracted_command_final_score(ca);
	int sb = ela_uboot_extracted_command_final_score(cb);

	if (sa != sb)
		return sb - sa;
	return strcmp(ca->name, cb->name);
}

int ela_uboot_extract_commands_from_blob(const uint8_t *blob,
					 size_t blob_len,
					 struct extracted_command **out_cmds,
					 size_t *out_count)
{
	static const char *const known_cmds[] = {
		"help", "printenv", "setenv", "env", "saveenv", "run", "echo", "version",
		"bdinfo", "boot", "bootm", "booti", "bootz", "bootd", "source", "reset",
		"mm", "mw", "md", "cmp", "cp", "go", "load", "loadb", "loadx", "loady",
		"fatload", "fatls", "ext4load", "ext4ls", "nand", "ubi", "ubifsmount",
		"ubifsls", "ubifsload", "sf", "mmc", "usb", "dhcp", "tftpboot", "ping",
		"crc32", "iminfo", "imls", "fdt", "itest", "true", "false", "sleep"
	};
	static const char *const stop_tokens[] = {
		"u-boot", "usage", "unknown", "command", "commands", "description",
		"firmware", "images", "image", "load", "data", "hash", "signature", "algo"
	};
	struct extracted_command *cmds = NULL;
	size_t count = 0;
	size_t i;
	char token[64];

	if (!blob || !blob_len || !out_cmds || !out_count)
		return -1;

	for (i = 0; i < blob_len;) {
		size_t start = i;
		size_t end;
		size_t len;
		bool known;
		bool context_seen;
		bool has_upper = false;
		bool has_sep = false;
		int occ_score = 0;
		size_t j;

		if (!ela_uboot_is_printable_ascii(blob[i])) {
			i++;
			continue;
		}

		while (i < blob_len && ela_uboot_is_printable_ascii(blob[i]))
			i++;
		end = i;
		len = end - start;

		if (len >= sizeof(token))
			continue;

		memcpy(token, blob + start, len);
		token[len] = '\0';

		if (!ela_uboot_token_looks_like_command_name(token))
			continue;

		for (j = 0; j < len; j++) {
			if (isupper((unsigned char)token[j]))
				has_upper = true;
			if (token[j] == '-' || token[j] == '_')
				has_sep = true;
		}

		if (token_in_list_ci(token, stop_tokens, ARRAY_SIZE(stop_tokens)))
			continue;

		known = token_in_list_ci(token, known_cmds, ARRAY_SIZE(known_cmds));
		context_seen = token_has_command_context(blob, blob_len, start, end);

		if (known)
			occ_score += 3;
		if (context_seen)
			occ_score += 3;
		if (!has_upper)
			occ_score += 1;
		if (len >= 3 && len <= 12)
			occ_score += 1;
		if (has_sep)
			occ_score += 1;

		if (occ_score < 2)
			continue;

		if (add_extracted_command(&cmds, &count, token, occ_score, known, context_seen) < 0) {
			ela_uboot_free_extracted_commands(cmds, count);
			return -1;
		}
	}

	if (count)
		qsort(cmds, count, sizeof(*cmds), extracted_command_cmp);

	*out_cmds = cmds;
	*out_count = count;
	return 0;
}

void ela_uboot_free_extracted_commands(struct extracted_command *cmds,
				       size_t count)
{
	size_t i;

	if (!cmds)
		return;

	for (i = 0; i < count; i++)
		free(cmds[i].name);
	free(cmds);
}
