// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_OUTPUT_FORMAT_H
#define ELA_UBOOT_OUTPUT_FORMAT_H

#include <string.h>

enum uboot_output_format {
	FW_OUTPUT_TXT = 0,
	FW_OUTPUT_CSV,
	FW_OUTPUT_JSON,
};

static inline enum uboot_output_format ela_uboot_detect_output_format(const char *fmt)
{
	if (fmt && !strcmp(fmt, "csv"))
		return FW_OUTPUT_CSV;
	if (fmt && !strcmp(fmt, "json"))
		return FW_OUTPUT_JSON;
	return FW_OUTPUT_TXT;
}

static inline const char *ela_uboot_http_content_type(enum uboot_output_format fmt)
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

#endif
