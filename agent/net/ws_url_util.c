// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ws_url_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char ela_ws_b64_alphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void ela_ws_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_sz)
{
	size_t i = 0;
	size_t o = 0;
	uint32_t v;

	while (i + 2 < in_len && o + 4 < out_sz) {
		v = ((uint32_t)in[i] << 16) |
		    ((uint32_t)in[i + 1] << 8) |
		    (uint32_t)in[i + 2];
		out[o++] = ela_ws_b64_alphabet[(v >> 18) & 0x3F];
		out[o++] = ela_ws_b64_alphabet[(v >> 12) & 0x3F];
		out[o++] = ela_ws_b64_alphabet[(v >> 6) & 0x3F];
		out[o++] = ela_ws_b64_alphabet[v & 0x3F];
		i += 3;
	}
	if (i < in_len && o + 4 < out_sz) {
		v = (uint32_t)in[i] << 16;
		if (i + 1 < in_len)
			v |= (uint32_t)in[i + 1] << 8;
		out[o++] = ela_ws_b64_alphabet[(v >> 18) & 0x3F];
		out[o++] = ela_ws_b64_alphabet[(v >> 12) & 0x3F];
		out[o++] = (i + 1 < in_len) ? ela_ws_b64_alphabet[(v >> 6) & 0x3F] : '=';
		out[o++] = '=';
	}
	if (o < out_sz)
		out[o] = '\0';
}

int ela_ws_parse_url(const char *url,
		     char *host, size_t host_sz,
		     uint16_t *port_out,
		     char *path, size_t path_sz,
		     int *is_tls_out)
{
	const char *p;
	const char *host_start;
	size_t host_len;
	const char *port_str;
	const char *path_start;
	unsigned long port;

	if (!url || !host || !port_out || !path || !is_tls_out)
		return -1;

	if (strncmp(url, "wss://", 6) == 0) {
		*is_tls_out = 1;
		p = url + 6;
		*port_out = 443;
	} else if (strncmp(url, "ws://", 5) == 0) {
		*is_tls_out = 0;
		p = url + 5;
		*port_out = 80;
	} else {
		return -1;
	}

	host_start = p;
	while (*p && *p != ':' && *p != '/')
		p++;

	host_len = (size_t)(p - host_start);
	if (host_len == 0 || host_len >= host_sz)
		return -1;
	memcpy(host, host_start, host_len);
	host[host_len] = '\0';

	if (*p == ':') {
		char *end = NULL;
		p++;
		port_str = p;
		while (*p >= '0' && *p <= '9')
			p++;
		if (p == port_str)
			return -1;
		port = strtoul(port_str, &end, 10);
		if (!end || end != p || port > 65535)
			return -1;
		*port_out = (uint16_t)port;
	}

	path_start = (*p == '/') ? p : "/";
	if (snprintf(path, path_sz, "%s", path_start) >= (int)path_sz)
		return -1;

	return 0;
}

int ela_ws_build_terminal_url(const char *base_url, const char *mac, char *out, size_t out_sz)
{
	size_t scheme_len;
	char stripped[512];
	size_t slen;
	int n;

	if (!base_url || !mac || !out || out_sz == 0)
		return -1;

	scheme_len = strncmp(base_url, "wss://", 6) == 0 ? 6 : 5;
	strncpy(stripped, base_url, sizeof(stripped) - 1);
	stripped[sizeof(stripped) - 1] = '\0';
	slen = strlen(stripped);
	while (slen > scheme_len && stripped[slen - 1] == '/')
		stripped[--slen] = '\0';

	n = snprintf(out, out_sz, "%s/terminal/%s", stripped, mac);
	return (n > 0 && (size_t)n < out_sz) ? 0 : -1;
}

int ela_ws_build_handshake_request(char *out,
				   size_t out_sz,
				   const char *host,
				   uint16_t port,
				   const char *path,
				   int is_tls,
				   const char *auth_token,
				   const char *websocket_key)
{
	int n;
	const char *auth_prefix = (auth_token && *auth_token) ? "Authorization: Bearer " : "";
	const char *auth_value = (auth_token && *auth_token) ? auth_token : "";
	const char *auth_suffix = (auth_token && *auth_token) ? "\r\n" : "";

	if (!out || out_sz == 0 || !host || !path || !websocket_key)
		return -1;

	if ((!is_tls && port != 80) || (is_tls && port != 443)) {
		n = snprintf(out, out_sz,
			     "GET %s HTTP/1.1\r\n"
			     "Host: %s:%u\r\n"
			     "Upgrade: websocket\r\n"
			     "Connection: Upgrade\r\n"
			     "Sec-WebSocket-Key: %s\r\n"
			     "Sec-WebSocket-Version: 13\r\n"
			     "%s%s%s"
			     "\r\n",
			     path, host, (unsigned int)port, websocket_key,
			     auth_prefix, auth_value, auth_suffix);
	} else {
		n = snprintf(out, out_sz,
			     "GET %s HTTP/1.1\r\n"
			     "Host: %s\r\n"
			     "Upgrade: websocket\r\n"
			     "Connection: Upgrade\r\n"
			     "Sec-WebSocket-Key: %s\r\n"
			     "Sec-WebSocket-Version: 13\r\n"
			     "%s%s%s"
			     "\r\n",
			     path, host, websocket_key,
			     auth_prefix, auth_value, auth_suffix);
	}

	if (n <= 0 || (size_t)n >= out_sz)
		return -1;
	return n;
}

int ela_is_ws_url(const char *url)
{
	if (!url)
		return 0;
	return strncmp(url, "ws://", 5) == 0 ||
	       strncmp(url, "wss://", 6) == 0;
}
