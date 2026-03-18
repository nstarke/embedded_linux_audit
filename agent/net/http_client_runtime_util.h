// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_HTTP_CLIENT_RUNTIME_UTIL_H
#define ELA_HTTP_CLIENT_RUNTIME_UTIL_H

#include <stdbool.h>
#include <stddef.h>

bool ela_http_body_is_chunked(const char *headers);
size_t ela_http_chunk_read_size(unsigned long remaining, size_t buf_size);
bool ela_http_should_try_udp_resolve_host(const char *host);
bool ela_http_should_retry_with_next_api_key(int status);
int ela_http_choose_upload_mac_address(const char *routed_mac,
				       const char *fallback_mac,
				       char *mac_buf,
				       size_t mac_buf_len);
int ela_http_format_status_error(long status, char *errbuf, size_t errbuf_len);
int ela_http_format_curl_transport_error(const char *detail, char *errbuf, size_t errbuf_len);

#endif
