// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef NET_API_KEY_UTIL_H
#define NET_API_KEY_UTIL_H

#include "api_key.h"

#include <stddef.h>

int ela_api_key_line_normalize(char *line);
int ela_api_key_add_unique(char keys[][ELA_API_KEY_MAX_LEN + 1], int *key_count, int max_keys, const char *key);

#endif
