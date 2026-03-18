// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_HTTP_WS_POLICY_UTIL_H
#define ELA_HTTP_WS_POLICY_UTIL_H

#include <stdbool.h>
#include <time.h>

enum ela_http_https_backend {
	ELA_HTTP_HTTPS_BACKEND_OPENSSL = 0,
	ELA_HTTP_HTTPS_BACKEND_WOLFSSL,
};

bool ela_http_status_is_success(int status_code);
enum ela_http_https_backend ela_http_choose_https_backend(bool is_powerpc);
bool ela_ws_should_send_keepalive(time_t now, time_t last_ping, time_t interval_seconds);

#endif
