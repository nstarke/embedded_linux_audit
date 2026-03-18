// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_HTTP_CLIENT_PROTOCOL_UTIL_H
#define ELA_HTTP_CLIENT_PROTOCOL_UTIL_H

#include <stddef.h>
#include <stdint.h>

int ela_http_parse_response_headers(const char *buf,
				    size_t len,
				    int *status_out,
				    size_t *header_len_out);
int ela_http_build_get_request(char **request_out,
			       size_t *request_len_out,
			       const char *path,
			       const char *host);
int ela_http_build_post_request(char **request_out,
				size_t *request_len_out,
				const char *path,
				const char *host,
				const char *content_type,
				size_t content_len,
				const char *auth_key,
				const uint8_t *body,
				size_t body_len);

#endif
