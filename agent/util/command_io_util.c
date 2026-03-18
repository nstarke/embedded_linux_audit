// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "command_io_util.h"

#include <stdio.h>
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
