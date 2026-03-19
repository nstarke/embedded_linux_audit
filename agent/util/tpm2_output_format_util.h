// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_TPM2_OUTPUT_FORMAT_UTIL_H
#define UTIL_TPM2_OUTPUT_FORMAT_UTIL_H

#include "output_buffer.h"

int ela_tpm2_is_valid_output_format(const char *format);
const char *ela_tpm2_output_content_type(const char *format);
int ela_tpm2_format_kv_record(struct output_buffer *buf,
			      const char *format,
			      const char *key,
			      const char *value);

#endif
