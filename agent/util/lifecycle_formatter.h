// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_LIFECYCLE_FORMATTER_H
#define UTIL_LIFECYCLE_FORMATTER_H

#include "output_buffer.h"

int ela_format_lifecycle_record(struct output_buffer *out,
				const char *format,
				const char *agent_timestamp,
				const char *command,
				const char *phase,
				int rc);
const char *ela_lifecycle_content_type(const char *format);

#endif
