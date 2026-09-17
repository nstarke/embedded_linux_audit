// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_COMMAND_IO_UTIL_H
#define UTIL_COMMAND_IO_UTIL_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

/* Print and flush locally, mirroring only stdout through the callback. */
void ela_command_emit_v(FILE *stream, const char *fmt, va_list ap, void (*mirror)(const char *data, size_t len));
const char *ela_execute_command_content_type(const char *output_format);
int ela_parse_download_file_args(int argc,
				 char **argv,
				 const char **url_out,
				 const char **output_path_out,
				 char *errbuf,
				 size_t errbuf_len);

#endif
