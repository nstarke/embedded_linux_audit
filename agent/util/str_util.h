// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_STR_UTIL_H
#define UTIL_STR_UTIL_H

#include <stddef.h>

int append_text(char **buf, size_t *len, size_t *cap, const char *text);
int append_bytes(char **buf, size_t *len, size_t *cap, const char *data, size_t data_len);
/* Append JSON string contents (without quotes) at *pos, then NUL-terminate. */
int ela_json_append_escaped(char *out, size_t out_len, size_t *pos, const char *value);
char *url_percent_encode(const char *text);

#endif /* UTIL_STR_UTIL_H */
