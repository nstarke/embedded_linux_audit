// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_COMMAND_PARSE_UTIL_H
#define UTIL_COMMAND_PARSE_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int ela_parse_positive_size_arg(const char *spec, size_t *count_out);
int ela_parse_u32(const char *text, uint32_t *value);
int ela_parse_u64(const char *text, uint64_t *value);
bool ela_parse_bool_string(const char *value, const char **normalized);
bool ela_output_format_is_valid(const char *format);
const char *ela_output_format_or_default(const char *format, const char *default_format);

#endif
