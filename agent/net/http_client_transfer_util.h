// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_HTTP_CLIENT_TRANSFER_UTIL_H
#define ELA_HTTP_CLIENT_TRANSFER_UTIL_H

#include <stdbool.h>
#include <stddef.h>

enum ela_http_transfer_transport {
	ELA_HTTP_TRANSPORT_INVALID = 0,
	ELA_HTTP_TRANSPORT_HTTP,
	ELA_HTTP_TRANSPORT_HTTPS,
};

struct ela_http_transfer_plan {
	enum ela_http_transfer_transport transport;
	char *normalized_uri;
	const char *effective_uri;
	const char *content_type;
};

int ela_http_prepare_post_plan(const char *uri,
			       const char *content_type,
			       struct ela_http_transfer_plan *plan,
			       char *errbuf,
			       size_t errbuf_len);
int ela_http_prepare_get_plan(const char *uri,
			      const char *output_path,
			      struct ela_http_transfer_plan *plan,
			      char *errbuf,
			      size_t errbuf_len);
void ela_http_transfer_plan_cleanup(struct ela_http_transfer_plan *plan);
bool ela_http_should_warn_unauthorized_status(int status);

#endif /* ELA_HTTP_CLIENT_TRANSFER_UTIL_H */
