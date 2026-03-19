// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_client_body_util.h"

#include "../util/str_util.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

int ela_http_build_identity_get_request(char **request_out,
					size_t *request_len_out,
					const char *path,
					const char *host)
{
	char *request = NULL;
	size_t request_len = 0;
	size_t request_cap = 0;

	if (!request_out || !request_len_out || !path || !host)
		return -1;

	if (append_text(&request, &request_len, &request_cap, "GET ") != 0 ||
	    append_text(&request, &request_len, &request_cap, path) != 0 ||
	    append_text(&request, &request_len, &request_cap, " HTTP/1.1\r\nHost: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, host) != 0 ||
	    append_text(&request, &request_len, &request_cap, "\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n") != 0) {
		free(request);
		return -1;
	}

	*request_out = request;
	*request_len_out = request_len;
	return 0;
}

int ela_http_parse_chunk_size_line(const char *line, unsigned long *chunk_len_out)
{
	char *end;
	unsigned long value;

	if (!line || !chunk_len_out)
		return -1;

	while (*line && isspace((unsigned char)*line))
		line++;

	value = strtoul(line, &end, 16);
	if (end == line)
		return -1;
	if (*end == ';') {
		while (*end && *end != '\r' && *end != '\n')
			end++;
	}
	if (*end != '\0' && *end != '\r' && *end != '\n')
		return -1;

	*chunk_len_out = value;
	return 0;
}
