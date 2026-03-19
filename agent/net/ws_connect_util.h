// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_WS_CONNECT_UTIL_H
#define ELA_WS_CONNECT_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void ela_ws_fill_nonce_from_seed(unsigned int seed, uint8_t nonce[16]);
void ela_ws_format_mac_bytes(const uint8_t mac[6], char *buf, size_t buf_sz);
bool ela_ws_mac_is_zero(const uint8_t mac[6]);

#endif
