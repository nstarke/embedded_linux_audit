// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "remote_copy_cmd_util.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int ela_remote_copy_validate_request(const char *path,
				     const char *output_tcp,
				     const char *output_http,
				     const char *output_https,
				     mode_t mode,
				     char *errbuf,
				     size_t errbuf_len)
{
	const char *output_uri = NULL;

	if (!path || path[0] != '/') {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "remote-copy requires an absolute file path: %s",
				 path ? path : "(null)");
		return -1;
	}
	if (output_http && strncmp(output_http, "http://", 7)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len,
				 "Invalid --output-http URI (expected http://host:port/...): %s",
				 output_http);
		return -1;
	}
	if (output_https && strncmp(output_https, "https://", 8)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len,
				 "Invalid --output-https URI (expected https://host:port/...): %s",
				 output_https);
		return -1;
	}
	if (output_http && output_https) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Use only one of --output-http or --output-https");
		return -1;
	}
	if (output_http)
		output_uri = output_http;
	if (output_https)
		output_uri = output_https;
	if ((!output_tcp || !*output_tcp) && (!output_uri || !*output_uri)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "remote-copy requires one of --output-tcp or --output-http");
		return -1;
	}
	if (output_tcp && output_uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "remote-copy accepts only one remote target at a time");
		return -1;
	}
	if (output_tcp && S_ISDIR(mode)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Directory uploads require --output-http");
		return -1;
	}
	if (output_tcp && S_ISLNK(mode)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Symlink uploads require --output-http");
		return -1;
	}
	return 0;
}
