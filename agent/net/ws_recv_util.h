// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_WS_RECV_UTIL_H
#define ELA_WS_RECV_UTIL_H

#include <stddef.h>
#include <stdint.h>

size_t ela_ws_payload_copy_len(uint64_t payload_len, size_t buf_sz);
size_t ela_ws_payload_skip_len(uint64_t payload_len, size_t buf_sz);

#endif
