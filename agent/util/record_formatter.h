// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_RECORD_FORMATTER_H
#define UTIL_RECORD_FORMATTER_H

#include "output_buffer.h"

#include <stddef.h>
#include <stdint.h>

int ela_format_arch_record(struct output_buffer *out,
			   const char *format,
			   const char *subcommand,
			   const char *value);
int ela_format_execute_command_record(struct output_buffer *out,
				      const char *format,
				      const char *command,
				      const char *command_output);
int ela_format_efi_var_record(struct output_buffer *out,
			      const char *format,
			      const char *guid_str,
			      const char *name,
			      uint32_t attributes,
			      size_t data_size,
			      const char *hex_data);

#endif
