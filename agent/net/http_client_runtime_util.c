// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_client_runtime_util.h"

#include "../util/http_protocol_util.h"

#include <stdio.h>
#include <string.h>

bool ela_http_body_is_chunked(const char *headers)
{
	return ela_http_headers_have_chunked_encoding(headers);
}

size_t ela_http_chunk_read_size(unsigned long remaining, size_t buf_size)
{
	if (buf_size == 0)
		return 0;
	return (size_t)(remaining > buf_size ? buf_size : remaining);
}

bool ela_http_should_try_udp_resolve_host(const char *host)
{
	int dots = 0;

	if (!host || !*host)
		return false;

	for (; *host; host++) {
		if (*host == '.') {
			dots++;
			continue;
		}
		if (*host < '0' || *host > '9')
			return true;
	}

	return dots != 3;
}

bool ela_http_should_retry_with_next_api_key(int status)
{
	return status == 401;
}

int ela_http_choose_upload_mac_address(const char *routed_mac,
				       const char *fallback_mac,
				       char *mac_buf,
				       size_t mac_buf_len)
{
	const char *selected = "00:00:00:00:00:00";

	if (!mac_buf || mac_buf_len < 18)
		return -1;

	if (routed_mac &&
	    ela_http_is_valid_mac_address_string(routed_mac) &&
	    !ela_http_is_zero_mac_address_string(routed_mac)) {
		selected = routed_mac;
	} else if (fallback_mac &&
		   ela_http_is_valid_mac_address_string(fallback_mac) &&
		   !ela_http_is_zero_mac_address_string(fallback_mac)) {
		selected = fallback_mac;
	}

	snprintf(mac_buf, mac_buf_len, "%s", selected);
	return 0;
}

int ela_http_format_status_error(long status, char *errbuf, size_t errbuf_len)
{
	if (!errbuf || errbuf_len == 0)
		return -1;

	snprintf(errbuf, errbuf_len, "HTTP status %ld", status);
	return 0;
}

int ela_http_format_curl_transport_error(const char *detail, char *errbuf, size_t errbuf_len)
{
	if (!errbuf || errbuf_len == 0 || !detail || !*detail)
		return -1;

	snprintf(errbuf, errbuf_len, "curl perform failed: %s", detail);
	return 0;
}
