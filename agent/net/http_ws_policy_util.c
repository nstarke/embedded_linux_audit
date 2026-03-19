// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_ws_policy_util.h"

bool ela_http_status_is_success(int status_code)
{
	return status_code >= 200 && status_code < 300;
}

enum ela_http_https_backend ela_http_choose_https_backend(bool is_powerpc)
{
	return is_powerpc ? ELA_HTTP_HTTPS_BACKEND_WOLFSSL
			  : ELA_HTTP_HTTPS_BACKEND_OPENSSL;
}

bool ela_ws_should_send_keepalive(time_t now, time_t last_ping, time_t interval_seconds)
{
	return now - last_ping >= interval_seconds;
}
