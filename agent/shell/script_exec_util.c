// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "script_exec_util.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

bool ela_script_is_http_source(const char *value)
{
	if (!value)
		return false;

	return !strncmp(value, "http://", 7) || !strncmp(value, "https://", 8);
}

const char *ela_script_basename(const char *path)
{
	const char *base;

	if (!path || !*path)
		return NULL;

	base = strrchr(path, '/');
	return base ? base + 1 : path;
}

char *ela_script_url_percent_encode(const char *text)
{
	static const char hex[] = "0123456789ABCDEF";
	const unsigned char *p;
	char *out;
	size_t out_len = 0;
	size_t text_len;

	if (!text)
		return NULL;

	text_len = strlen(text);
	out = malloc(text_len * 3 + 1);
	if (!out)
		return NULL;

	for (p = (const unsigned char *)text; *p; p++) {
		if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
			out[out_len++] = (char)*p;
		} else {
			out[out_len++] = '%';
			out[out_len++] = hex[*p >> 4];
			out[out_len++] = hex[*p & 0x0F];
		}
	}
	out[out_len] = '\0';
	return out;
}

char *ela_script_build_fallback_uri(const char *output_uri, const char *script_source)
{
	const char *scheme_end;
	const char *authority;
	const char *authority_end;
	const char *script_name;
	char *escaped_script_name;
	char *uri;
	size_t prefix_len;
	size_t route_len;
	size_t escaped_len;

	if (!output_uri || !*output_uri || !script_source || !*script_source)
		return NULL;

	scheme_end = strstr(output_uri, "://");
	if (!scheme_end)
		return NULL;

	authority = scheme_end + 3;
	authority_end = authority;
	while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
		authority_end++;

	script_name = ela_script_basename(script_source);
	if (!script_name || !*script_name)
		return NULL;

	escaped_script_name = ela_script_url_percent_encode(script_name);
	if (!escaped_script_name)
		return NULL;

	prefix_len = (size_t)(authority_end - output_uri);
	route_len = strlen("/scripts/");
	escaped_len = strlen(escaped_script_name);
	uri = malloc(prefix_len + route_len + escaped_len + 1);
	if (!uri) {
		free(escaped_script_name);
		return NULL;
	}

	memcpy(uri, output_uri, prefix_len);
	memcpy(uri + prefix_len, "/scripts/", route_len);
	memcpy(uri + prefix_len + route_len, escaped_script_name, escaped_len + 1);
	free(escaped_script_name);
	return uri;
}

char *ela_script_trim(char *s)
{
	char *end;

	if (!s)
		return NULL;

	while (*s && isspace((unsigned char)*s))
		s++;

	if (!*s)
		return s;

	end = s + strlen(s) - 1;
	while (end >= s && isspace((unsigned char)*end)) {
		*end = '\0';
		end--;
	}

	return s;
}
