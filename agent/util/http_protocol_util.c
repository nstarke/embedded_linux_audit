// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_protocol_util.h"

#include "str_util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ela_http_parse_status_code_from_headers(const char *headers)
{
	int status = 0;

	if (!headers)
		return -1;
	if (sscanf(headers, "HTTP/%*u.%*u %d", &status) != 1)
		return -1;
	return status;
}

bool ela_http_headers_have_chunked_encoding(const char *headers)
{
	return headers && strstr(headers, "\nTransfer-Encoding: chunked\r") != NULL;
}

bool ela_http_is_valid_mac_address_string(const char *value)
{
	int i;

	if (!value)
		return false;

	for (i = 0; i < 17; i++) {
		char ch = value[i];

		if (i % 3 == 2) {
			if (ch != ':')
				return false;
		} else if (!isxdigit((unsigned char)ch)) {
			return false;
		}
	}

	return value[17] == '\0';
}

bool ela_http_is_zero_mac_address_string(const char *value)
{
	return value && !strcmp(value, "00:00:00:00:00:00");
}

int ela_http_build_basic_request(char **request_out,
				 const char *method,
				 const char *host,
				 const char *path,
				 uint16_t port,
				 bool https,
				 const char *content_type,
				 size_t content_length,
				 const char *auth_key)
{
	char *request = NULL;
	size_t request_len = 0;
	size_t request_cap = 0;
	char content_len_buf[32];
	char host_header[320];
	uint16_t default_port;

	if (!request_out || !method || !host || !path)
		return -1;

	default_port = https ? 443 : 80;
	if (port != 0 && port != default_port)
		snprintf(host_header, sizeof(host_header), "%s:%u", host, (unsigned int)port);
	else
		snprintf(host_header, sizeof(host_header), "%s", host);
	snprintf(content_len_buf, sizeof(content_len_buf), "%zu", content_length);

	if (append_text(&request, &request_len, &request_cap, method) != 0 ||
	    append_text(&request, &request_len, &request_cap, " ") != 0 ||
	    append_text(&request, &request_len, &request_cap, path) != 0 ||
	    append_text(&request, &request_len, &request_cap, " HTTP/1.1\r\nHost: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, host_header) != 0 ||
	    append_text(&request, &request_len, &request_cap, "\r\nConnection: close\r\n") != 0)
		goto fail;

	if (content_type) {
		if (append_text(&request, &request_len, &request_cap, "Content-Type: ") != 0 ||
		    append_text(&request, &request_len, &request_cap, content_type) != 0 ||
		    append_text(&request, &request_len, &request_cap, "\r\n") != 0)
			goto fail;
	}

	if (append_text(&request, &request_len, &request_cap, "Content-Length: ") != 0 ||
	    append_text(&request, &request_len, &request_cap, content_len_buf) != 0 ||
	    append_text(&request, &request_len, &request_cap, "\r\n") != 0)
		goto fail;

	if (auth_key && *auth_key) {
		if (append_text(&request, &request_len, &request_cap, "Authorization: Bearer ") != 0 ||
		    append_text(&request, &request_len, &request_cap, auth_key) != 0 ||
		    append_text(&request, &request_len, &request_cap, "\r\n") != 0)
			goto fail;
	}

	if (append_text(&request, &request_len, &request_cap, "\r\n") != 0)
		goto fail;

	*request_out = request;
	return 0;

fail:
	free(request);
	return -1;
}
