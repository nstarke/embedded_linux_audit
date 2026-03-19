// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_HTTP_PROTOCOL_UTIL_H
#define UTIL_HTTP_PROTOCOL_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int ela_http_parse_status_code_from_headers(const char *headers);
bool ela_http_headers_have_chunked_encoding(const char *headers);
bool ela_http_is_valid_mac_address_string(const char *value);
bool ela_http_is_zero_mac_address_string(const char *value);
int ela_http_build_basic_request(char **request_out,
				 const char *method,
				 const char *host,
				 const char *path,
				 uint16_t port,
				 bool https,
				 const char *content_type,
				 size_t content_length,
				 const char *auth_key);

#endif
