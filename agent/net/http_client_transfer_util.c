// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_client_transfer_util.h"

#include "../util/http_uri_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int prepare_plan_common(const char *uri,
			       struct ela_http_transfer_plan *plan,
			       char *errbuf,
			       size_t errbuf_len)
{
	bool is_http;
	bool is_https;

	if (!plan)
		return -1;

	memset(plan, 0, sizeof(*plan));
	is_http = uri && strncmp(uri, "http://", 7) == 0;
	is_https = uri && strncmp(uri, "https://", 8) == 0;

	if (!uri || !*uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP URI is empty");
		return -1;
	}

	if (!is_http && !is_https) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len,
				 "unsupported URI scheme (expected http:// or https://)");
		return -1;
	}

	plan->transport = is_https ? ELA_HTTP_TRANSPORT_HTTPS
				   : ELA_HTTP_TRANSPORT_HTTP;
	plan->normalized_uri =
		ela_http_uri_normalize_default_port(uri, is_https ? 443 : 80);
	if (!plan->normalized_uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to normalize HTTP URI");
		plan->transport = ELA_HTTP_TRANSPORT_INVALID;
		return -1;
	}

	plan->effective_uri = plan->normalized_uri;
	return 0;
}

int ela_http_prepare_post_plan(const char *uri,
			       const char *content_type,
			       struct ela_http_transfer_plan *plan,
			       char *errbuf,
			       size_t errbuf_len)
{
	if (prepare_plan_common(uri, plan, errbuf, errbuf_len) != 0)
		return -1;

	plan->content_type = (content_type && *content_type)
			   ? content_type
			   : "text/plain; charset=utf-8";
	return 0;
}

int ela_http_prepare_get_plan(const char *uri,
			      const char *output_path,
			      struct ela_http_transfer_plan *plan,
			      char *errbuf,
			      size_t errbuf_len)
{
	if (!output_path || !*output_path) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP GET requires URI and output path");
		return -1;
	}

	if (prepare_plan_common(uri, plan, errbuf, errbuf_len) != 0) {
		if (errbuf && errbuf_len && strcmp(errbuf, "HTTP URI is empty") == 0)
			snprintf(errbuf, errbuf_len, "HTTP GET requires URI and output path");
		return -1;
	}

	return 0;
}

void ela_http_transfer_plan_cleanup(struct ela_http_transfer_plan *plan)
{
	if (!plan)
		return;
	free(plan->normalized_uri);
	plan->normalized_uri = NULL;
	plan->effective_uri = NULL;
	plan->content_type = NULL;
	plan->transport = ELA_HTTP_TRANSPORT_INVALID;
}

bool ela_http_should_warn_unauthorized_status(int status)
{
	return status == 401;
}
