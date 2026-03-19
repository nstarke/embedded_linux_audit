// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_WS_INTERACTIVE_UTIL_H
#define ELA_WS_INTERACTIVE_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void ela_ws_default_mask_key(uint8_t mask[4]);
bool ela_ws_socket_readable(int fd_ready, bool is_tls, int pending_bytes);

#endif
