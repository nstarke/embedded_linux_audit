// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_env_scan_util.h"

#include <stdlib.h>
#include <string.h>

int ela_uboot_env_add_or_merge_candidate(struct ela_uboot_env_candidate **cands,
					 size_t *count,
					 uint64_t cfg_off,
					 bool crc_standard,
					 bool crc_redundant)
{
	struct ela_uboot_env_candidate *tmp;
	size_t i;

	if (!cands || !count)
		return -1;

	for (i = 0; i < *count; i++) {
		if ((*cands)[i].cfg_off != cfg_off)
			continue;
		(*cands)[i].crc_standard = (*cands)[i].crc_standard || crc_standard;
		(*cands)[i].crc_redundant = (*cands)[i].crc_redundant || crc_redundant;
		return 0;
	}

	tmp = realloc(*cands, (*count + 1) * sizeof(**cands));
	if (!tmp)
		return -1;
	*cands = tmp;
	(*cands)[*count].cfg_off = cfg_off;
	(*cands)[*count].crc_standard = crc_standard;
	(*cands)[*count].crc_redundant = crc_redundant;
	(*count)++;
	return 0;
}

bool ela_uboot_env_is_http_write_source(const char *s)
{
	if (!s)
		return false;
	return !strncmp(s, "http://", 7) || !strncmp(s, "https://", 8);
}
