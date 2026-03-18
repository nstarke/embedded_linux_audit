// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "command_parse_util.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

int ela_parse_positive_size_arg(const char *spec, size_t *count_out)
{
	char *end = NULL;
	unsigned long value;

	if (!spec || !*spec || !count_out)
		return -1;
	if (spec[0] == '-')
		return -1;

	errno = 0;
	value = strtoul(spec, &end, 10);
	if (errno != 0 || !end || *end != '\0' || value == 0 || (unsigned long)(size_t)value != value)
		return -1;

	*count_out = (size_t)value;
	return 0;
}

int ela_parse_u32(const char *text, uint32_t *value)
{
	char *end = NULL;
	unsigned long parsed;

	if (!text || !*text || !value)
		return -1;

	errno = 0;
	parsed = strtoul(text, &end, 0);
	if (errno != 0 || !end || *end != '\0' || parsed > UINT32_MAX)
		return -1;

	*value = (uint32_t)parsed;
	return 0;
}

int ela_parse_u64(const char *text, uint64_t *value)
{
	char *end = NULL;
	unsigned long long parsed;

	if (!text || !value)
		return -1;

	errno = 0;
	parsed = strtoull(text, &end, 0);
	while (end && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
		end++;
	if (errno != 0 || !end || end == text || *end != '\0')
		return -1;

	*value = (uint64_t)parsed;
	return 0;
}

bool ela_parse_bool_string(const char *value, const char **normalized)
{
	if (!value || !normalized)
		return false;

	if (!strcmp(value, "1") || !strcmp(value, "true") || !strcmp(value, "yes") ||
	    !strcmp(value, "on")) {
		*normalized = "true";
		return true;
	}

	if (!strcmp(value, "0") || !strcmp(value, "false") || !strcmp(value, "no") ||
	    !strcmp(value, "off")) {
		*normalized = "false";
		return true;
	}

	return false;
}

bool ela_output_format_is_valid(const char *format)
{
	return format &&
	       (!strcmp(format, "txt") ||
		!strcmp(format, "csv") ||
		!strcmp(format, "json"));
}

const char *ela_output_format_or_default(const char *format, const char *default_format)
{
	if (format && *format)
		return format;
	return default_format;
}
