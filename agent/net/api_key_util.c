// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "api_key_util.h"

#include <string.h>

int ela_api_key_line_normalize(char *line)
{
	size_t len;

	if (!line)
		return -1;
	len = strlen(line);
	while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
		line[--len] = '\0';
	return len > 0 ? 0 : -1;
}

int ela_api_key_add_unique(char keys[][ELA_API_KEY_MAX_LEN + 1], int *key_count, int max_keys, const char *key)
{
	int i;

	if (!keys || !key_count || !key || !*key)
		return -1;
	if (strlen(key) > ELA_API_KEY_MAX_LEN || *key_count >= max_keys)
		return -1;
	for (i = 0; i < *key_count; i++) {
		if (!strcmp(keys[i], key))
			return 1;
	}
	strncpy(keys[*key_count], key, ELA_API_KEY_MAX_LEN);
	keys[*key_count][ELA_API_KEY_MAX_LEN] = '\0';
	(*key_count)++;
	return 0;
}
