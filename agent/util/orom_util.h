// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_OROM_UTIL_H
#define UTIL_OROM_UTIL_H

#include "output_buffer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum orom_output_format {
	OROM_FMT_TXT = 0,
	OROM_FMT_CSV,
	OROM_FMT_JSON,
};

enum orom_output_format ela_orom_detect_output_format(const char *format);
bool ela_orom_rom_matches_mode(const uint8_t *buf, size_t len, const char *fw_mode);
int ela_orom_format_record(struct output_buffer *out,
			   enum orom_output_format fmt,
			   const char *fw_mode,
			   const char *record,
			   const char *rom_path,
			   size_t size,
			   const char *type,
			   const char *value);

#endif
