// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_HTTP_URI_UTIL_H
#define UTIL_HTTP_URI_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct parsed_http_uri {
	bool https;
	char host[256];
	uint16_t port;
	char path[PATH_MAX];
};

int parse_http_uri(const char *uri, struct parsed_http_uri *parsed);
char *ela_http_uri_normalize_default_port(const char *uri, uint16_t default_port);
int ela_parse_http_output_uri(const char *uri,
			      const char **output_http,
			      const char **output_https,
			      char *errbuf,
			      size_t errbuf_len);
int ela_parse_http_uri_host(const char *uri, char *host_buf, size_t host_buf_len);

#endif
