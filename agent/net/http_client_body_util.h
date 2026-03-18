// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_HTTP_CLIENT_BODY_UTIL_H
#define ELA_HTTP_CLIENT_BODY_UTIL_H

#include <stddef.h>

int ela_http_build_identity_get_request(char **request_out,
					size_t *request_len_out,
					const char *path,
					const char *host);
int ela_http_parse_chunk_size_line(const char *line, unsigned long *chunk_len_out);

#endif
