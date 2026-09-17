// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "command_io_util.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *ela_execute_command_content_type(const char *output_format)
{
	if (output_format && !strcmp(output_format, "csv"))
		return "text/csv; charset=utf-8";
	if (output_format && !strcmp(output_format, "json"))
		return "application/json; charset=utf-8";
	return "text/plain; charset=utf-8";
}

int ela_parse_download_file_args(int argc,
				 char **argv,
				 const char **url_out,
				 const char **output_path_out,
				 char *errbuf,
				 size_t errbuf_len)
{
	const char *url;
	const char *output_path;

	if (!url_out || !output_path_out)
		return -1;
	if (argc < 1) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "download-file requires a URL beginning with http:// or https://");
		return -1;
	}

	url = argv[0];
	if (strncmp(url, "http://", 7) && strncmp(url, "https://", 8)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "download-file requires a URL beginning with http:// or https://: %s", url);
		return -1;
	}
	if (argc < 2) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "download-file requires an output path");
		return -1;
	}

	output_path = argv[1];
	if (!output_path || !*output_path) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "download-file requires a non-empty output path");
		return -1;
	}
	if (argc > 2) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Unexpected argument: %s", argv[2]);
		return -1;
	}

	*url_out = url;
	*output_path_out = output_path;
	return 0;
}

void ela_command_emit_v(FILE *stream, const char *fmt, va_list ap, void (*mirror)(const char *data, size_t len))
{
	va_list aq;
	va_list ar;
	char stack[1024];
	char *dyn = NULL;
	int needed;
	bool mirror_to_remote;

	mirror_to_remote = (stream == stdout && mirror != NULL);

	va_copy(aq, ap);
	va_copy(ar, ap);
	vfprintf(stream, fmt, ap);
	fflush(stream);

	needed = vsnprintf(stack, sizeof(stack), fmt, aq);
	va_end(aq);

	if (needed < 0) {
		va_end(ar);
		return;
	}

	if ((size_t)needed < sizeof(stack)) {
		if (mirror_to_remote) {
			mirror(stack, (size_t)needed);
		}
		va_end(ar);
		return;
	}

	dyn = malloc((size_t)needed + 1);
	if (!dyn) {
		va_end(ar);
		return;
	}

	vsnprintf(dyn, (size_t)needed + 1, fmt, ar);
	va_end(ar);
	if (mirror_to_remote) {
		mirror(dyn, (size_t)needed);
	}
	free(dyn);
}
