// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_uri_util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int parse_http_uri(const char *uri, struct parsed_http_uri *parsed)
{
	const char *scheme_end;
	const char *authority;
	const char *authority_end;
	const char *host_start;
	const char *host_end;
	const char *path_start;
	const char *at;
	const char *port_sep = NULL;
	char port_buf[8];
	size_t host_len;
	size_t path_len;

	if (!uri || !parsed)
		return -1;

	memset(parsed, 0, sizeof(*parsed));
	scheme_end = strstr(uri, "://");
	if (!scheme_end)
		return -1;

	if ((size_t)(scheme_end - uri) == 4 && !strncmp(uri, "http", 4)) {
		parsed->https = false;
		parsed->port = 80;
	} else if ((size_t)(scheme_end - uri) == 5 && !strncmp(uri, "https", 5)) {
		parsed->https = true;
		parsed->port = 443;
	} else {
		return -1;
	}

	authority = scheme_end + 3;
	authority_end = authority;
	while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
		authority_end++;
	path_start = authority_end;

	at = memchr(authority, '@', (size_t)(authority_end - authority));
	host_start = at ? (at + 1) : authority;
	if (host_start >= authority_end)
		return -1;

	if (*host_start == '[')
		return -1;

	host_end = host_start;
	while (host_end < authority_end && *host_end != ':')
		host_end++;
	if (host_end < authority_end && *host_end == ':')
		port_sep = host_end;

	host_len = (size_t)(host_end - host_start);
	if (!host_len || host_len >= sizeof(parsed->host))
		return -1;
	memcpy(parsed->host, host_start, host_len);
	parsed->host[host_len] = '\0';

	if (port_sep) {
		char *end;
		unsigned long port_ul;
		size_t port_len = (size_t)(authority_end - (port_sep + 1));
		if (!port_len || port_len >= sizeof(port_buf))
			return -1;
		memcpy(port_buf, port_sep + 1, port_len);
		port_buf[port_len] = '\0';
		errno = 0;
		port_ul = strtoul(port_buf, &end, 10);
		if (errno || !end || *end || port_ul == 0 || port_ul > 65535)
			return -1;
		parsed->port = (uint16_t)port_ul;
	}

	if (!*path_start) {
		parsed->path[0] = '/';
		parsed->path[1] = '\0';
		return 0;
	}

	path_len = strlen(path_start);
	if (path_len >= sizeof(parsed->path))
		return -1;
	memcpy(parsed->path, path_start, path_len + 1);
	return 0;
}

char *ela_http_uri_normalize_default_port(const char *uri, uint16_t default_port)
{
	const char *scheme_end;
	const char *authority;
	const char *authority_end;
	const char *path;
	const char *host_start;
	const char *at;
	const char *port_sep = NULL;
	char port_buf[8];
	char *out;
	size_t prefix_len;
	size_t suffix_len;
	size_t port_len;

	if (!uri || !*uri)
		return NULL;

	scheme_end = strstr(uri, "://");
	if (!scheme_end)
		return strdup(uri);

	authority = scheme_end + 3;
	authority_end = authority;
	while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
		authority_end++;

	if (authority == authority_end)
		return strdup(uri);

	path = authority_end;
	at = memchr(authority, '@', (size_t)(authority_end - authority));
	host_start = at ? (at + 1) : authority;

	if (host_start >= authority_end)
		return strdup(uri);

	if (*host_start == '[') {
		const char *host_end = memchr(host_start, ']', (size_t)(authority_end - host_start));
		if (!host_end)
			return strdup(uri);
		if (host_end + 1 < authority_end && *(host_end + 1) == ':')
			port_sep = host_end + 1;
	} else {
		for (const char *p = host_start; p < authority_end; p++) {
			if (*p == ':')
				port_sep = p;
		}
	}

	if (port_sep)
		return strdup(uri);

	snprintf(port_buf, sizeof(port_buf), ":%u", (unsigned int)default_port);
	port_len = strlen(port_buf);
	prefix_len = (size_t)(authority_end - uri);
	suffix_len = strlen(path);

	out = malloc(prefix_len + port_len + suffix_len + 1);
	if (!out)
		return NULL;

	memcpy(out, uri, prefix_len);
	memcpy(out + prefix_len, port_buf, port_len);
	memcpy(out + prefix_len + port_len, path, suffix_len + 1);
	return out;
}

int ela_parse_http_output_uri(const char *uri,
			      const char **output_http,
			      const char **output_https,
			      char *errbuf,
			      size_t errbuf_len)
{
	if (output_http)
		*output_http = NULL;
	if (output_https)
		*output_https = NULL;
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (!uri || !*uri)
		return 0;

	if (!strncmp(uri, "http://", 7)) {
		if (output_http)
			*output_http = uri;
		return 0;
	}

	if (!strncmp(uri, "https://", 8)) {
		if (output_https)
			*output_https = uri;
		return 0;
	}

	if (errbuf && errbuf_len)
		snprintf(errbuf,
			 errbuf_len,
			 "Invalid --output-http URI (expected http://host:port/... or https://host:port/...): %s",
			 uri);
	return -1;
}

int ela_parse_http_uri_host(const char *uri, char *host_buf, size_t host_buf_len)
{
	const char *scheme_end;
	const char *authority;
	const char *authority_end;
	const char *host_start;
	const char *host_end;
	const char *at;
	size_t host_len;

	if (!uri || !*uri || !host_buf || host_buf_len < 2)
		return -1;

	scheme_end = strstr(uri, "://");
	if (!scheme_end)
		return -1;

	authority = scheme_end + 3;
	authority_end = authority;
	while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
		authority_end++;

	at = memchr(authority, '@', (size_t)(authority_end - authority));
	host_start = at ? (at + 1) : authority;
	if (host_start >= authority_end)
		return -1;

	if (*host_start == '[') {
		host_start++;
		host_end = memchr(host_start, ']', (size_t)(authority_end - host_start));
		if (!host_end)
			return -1;
	} else {
		host_end = host_start;
		while (host_end < authority_end && *host_end != ':')
			host_end++;
	}

	host_len = (size_t)(host_end - host_start);
	if (host_len == 0 || host_len >= host_buf_len)
		return -1;

	memcpy(host_buf, host_start, host_len);
	host_buf[host_len] = '\0';
	return 0;
}
