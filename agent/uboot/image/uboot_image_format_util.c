// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_image_format_util.h"

#include <string.h>
#include <strings.h>

enum uboot_output_format ela_uboot_image_detect_output_format(const char *fmt)
{
	if (!fmt || !*fmt || !strcmp(fmt, "txt"))
		return FW_OUTPUT_TXT;
	if (!strcmp(fmt, "csv"))
		return FW_OUTPUT_CSV;
	if (!strcmp(fmt, "json"))
		return FW_OUTPUT_JSON;
	return FW_OUTPUT_TXT;
}

const char *ela_uboot_image_http_content_type(enum uboot_output_format fmt)
{
	switch (fmt) {
	case FW_OUTPUT_JSON:
		return "application/x-ndjson; charset=utf-8";
	case FW_OUTPUT_CSV:
		return "text/csv; charset=utf-8";
	case FW_OUTPUT_TXT:
	default:
		return "text/plain; charset=utf-8";
	}
}

size_t ela_uboot_image_align_up_4(size_t v)
{
	return (v + 3U) & ~((size_t)3U);
}

bool ela_uboot_image_str_contains_token_ci(const char *haystack, const char *needle)
{
	size_t needle_len;
	const char *p;

	if (!haystack || !needle)
		return false;

	needle_len = strlen(needle);
	if (!needle_len)
		return true;

	for (p = haystack; *p; p++) {
		if (!strncasecmp(p, needle, needle_len))
			return true;
	}

	return false;
}
