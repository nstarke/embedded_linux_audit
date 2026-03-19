// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_FILE_SCAN_FORMATTER_H
#define UTIL_FILE_SCAN_FORMATTER_H

#include "output_buffer.h"

#include <stddef.h>

int ela_format_grep_match_record(struct output_buffer *out,
				 const char *path,
				 unsigned long line_no,
				 const char *line);
int ela_format_symlink_record(struct output_buffer *out,
			      const char *format,
			      const char *link_path,
			      const char *target_path);
const char *ela_output_format_content_type(const char *format,
					   const char *default_content_type);

#endif
