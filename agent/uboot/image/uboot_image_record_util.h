// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_IMAGE_RECORD_UTIL_H
#define ELA_UBOOT_IMAGE_RECORD_UTIL_H

#include "uboot/image/uboot_image_internal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int ela_uboot_image_format_record(enum uboot_output_format fmt,
				  bool *csv_header_emitted,
				  const char *record,
				  const char *dev,
				  uint64_t off,
				  const char *type,
				  const char *value,
				  char **out);
int ela_uboot_image_format_verbose(enum uboot_output_format fmt,
				   bool verbose,
				   bool *csv_header_emitted,
				   const char *dev,
				   uint64_t off,
				   const char *msg,
				   char **out);
int ela_uboot_image_format_signature(enum uboot_output_format fmt,
				     bool *csv_header_emitted,
				     const char *dev,
				     uint64_t off,
				     const char *kind,
				     char **out);
bool ela_uboot_image_matches_text_pattern(const uint8_t *buf,
					  size_t buf_len,
					  size_t pos,
					  const char *pattern);
const char *ela_uboot_image_classify_signature_kind(bool uimage_valid,
						    bool fit_valid,
						    bool text_match);

#endif
