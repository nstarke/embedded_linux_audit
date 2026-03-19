// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_client_protocol_util.h"

#include "../util/str_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ela_http_parse_response_headers(const char *buf,
				    size_t len,
				    int *status_out,
				    size_t *header_len_out)
{
	size_t i;
	const char *line_end;
	char status_line[64];
	size_t status_len;

	if (!buf || !status_out || !header_len_out)
		return -1;

	for (i = 0; i + 3 < len; i++) {
		if (buf[i] == '\r' && buf[i + 1] == '\n' &&
		    buf[i + 2] == '\r' && buf[i + 3] == '\n')
			break;
	}
	if (i + 3 >= len)
		return 1;

	line_end = strstr(buf, "\r\n");
	if (!line_end || (size_t)(line_end - buf) >= sizeof(status_line))
		return -1;

	status_len = (size_t)(line_end - buf);
	memcpy(status_line, buf, status_len);
	status_line[status_len] = '\0';

	if (sscanf(status_line, "HTTP/%*u.%*u %d", status_out) != 1)
		return -1;

	*header_len_out = i + 4;
	return 0;
}

int ela_http_build_get_request(char **request_out,
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
	    append_text(&request, &request_len, &request_cap, "\r\nConnection: close\r\n\r\n") != 0) {
		free(request);
		return -1;
	}

	*request_out = request;
	*request_len_out = request_len;
	return 0;
}

int ela_http_build_post_request(char **request_out,
				size_t *request_len_out,
				const char *path,
				const char *host,
				const char *content_type,
				size_t content_len,
				const char *auth_key,
				const uint8_t *body,
				size_t body_len)
{
	char *request = NULL;
	size_t request_len = 0;
	size_t request_cap = 0;
	char content_len_buf[32];

	if (!request_out || !request_len_out || !path || !host || !content_type)
		return -1;

	snprintf(content_len_buf, sizeof(content_len_buf), "%zu", content_len);
	if (append_text(&request, &request_len, &request_cap, "POST ") != 0 ||
	    append_text(&request, &request_len, &request_cap, path) != 0 ||
	    append_text(&request, &request_len, &request_cap, " HTTP/1.1\r\nHost: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, host) != 0 ||
	    append_text(&request, &request_len, &request_cap, "\r\nConnection: close\r\nContent-Type: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, content_type) != 0 ||
	    append_text(&request, &request_len, &request_cap, "\r\nContent-Length: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, content_len_buf) != 0) {
		free(request);
		return -1;
	}

	if (auth_key && *auth_key) {
		if (append_text(&request, &request_len, &request_cap, "\r\nAuthorization: Bearer ") != 0 ||
		    append_text(&request, &request_len, &request_cap, auth_key) != 0) {
			free(request);
			return -1;
		}
	}

	if (append_text(&request, &request_len, &request_cap, "\r\n\r\n") != 0) {
		free(request);
		return -1;
	}

	if (body && body_len > 0 &&
	    append_bytes(&request, &request_len, &request_cap, (const char *)body, body_len) != 0) {
		free(request);
		return -1;
	}

	*request_out = request;
	*request_len_out = request_len;
	return 0;
}
