// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef NET_WS_FRAME_UTIL_H
#define NET_WS_FRAME_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define ELA_WS_OPCODE_TEXT  0x01
#define ELA_WS_OPCODE_CLOSE 0x08
#define ELA_WS_OPCODE_PING  0x09
#define ELA_WS_OPCODE_PONG  0x0A

int ela_ws_build_masked_frame(uint8_t opcode,
			      const uint8_t mask[4],
			      const char *payload,
			      size_t payload_len,
			      uint8_t **frame_out,
			      size_t *frame_len_out);
ssize_t ela_ws_parse_frame_bytes(const uint8_t *frame,
				 size_t frame_len,
				 uint8_t *opcode_out,
				 char *payload_out,
				 size_t payload_out_sz);

#endif
