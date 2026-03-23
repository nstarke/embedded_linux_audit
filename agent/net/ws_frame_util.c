// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ws_frame_util.h"

#include <stdlib.h>
#include <string.h>

int ela_ws_build_masked_frame(uint8_t opcode,
			      const uint8_t mask[4],
			      const char *payload,
			      size_t payload_len,
			      uint8_t **frame_out,
			      size_t *frame_len_out)
{
	uint8_t *frame;
	size_t hdr_len = 2;
	size_t i;

	if (!mask || !frame_out || !frame_len_out || (!payload && payload_len))
		return -1;

	if (payload_len < 126) {
		hdr_len = 2;
	} else if (payload_len < 65536) {
		hdr_len = 4;
	} else {
		hdr_len = 10;
	}

	frame = calloc(hdr_len + 4 + payload_len, 1);
	if (!frame)
		return -1;

	frame[0] = 0x80 | opcode;
	if (payload_len < 126) {
		frame[1] = 0x80 | (uint8_t)payload_len;
	} else if (payload_len < 65536) {
		frame[1] = 0x80 | 126;
		frame[2] = (uint8_t)(payload_len >> 8);
		frame[3] = (uint8_t)payload_len;
	} else {
		frame[1] = 0x80 | 127;
		frame[2] = (uint8_t)(payload_len >> 56);
		frame[3] = (uint8_t)(payload_len >> 48);
		frame[4] = (uint8_t)(payload_len >> 40);
		frame[5] = (uint8_t)(payload_len >> 32);
		frame[6] = (uint8_t)(payload_len >> 24);
		frame[7] = (uint8_t)(payload_len >> 16);
		frame[8] = (uint8_t)(payload_len >> 8);
		frame[9] = (uint8_t)payload_len;
	}
	memcpy(frame + hdr_len, mask, 4);
	for (i = 0; i < payload_len; i++)
		frame[hdr_len + 4 + i] = (uint8_t)payload[i] ^ mask[i & 3];

	*frame_out = frame;
	*frame_len_out = hdr_len + 4 + payload_len;
	return 0;
}

ssize_t ela_ws_parse_frame_bytes(const uint8_t *frame,
				 size_t frame_len,
				 uint8_t *opcode_out,
				 char *payload_out,
				 size_t payload_out_sz)
{
	uint64_t payload_len;
	uint8_t mask[4] = {0};
	size_t pos = 2;
	size_t i;
	int masked;
	size_t copy_len;

	if (!frame || frame_len < 2 || !payload_out || payload_out_sz == 0)
		return -1;

	if (opcode_out)
		*opcode_out = frame[0] & 0x0F;
	masked = (frame[1] & 0x80) != 0;
	payload_len = (uint64_t)(frame[1] & 0x7F);

	if (payload_len == 126) {
		if (frame_len < pos + 2)
			return -1;
		payload_len = ((uint64_t)frame[pos] << 8) | frame[pos + 1];
		pos += 2;
	} else if (payload_len == 127) {
		if (frame_len < pos + 8)
			return -1;
		payload_len = 0;
		for (i = 0; i < 8; i++)
			payload_len = (payload_len << 8) | frame[pos + i];
		pos += 8;
	}

	if (masked) {
		if (frame_len < pos + 4)
			return -1;
		memcpy(mask, frame + pos, 4);
		pos += 4;
	}

	if (frame_len < pos + payload_len)
		return -1;

	copy_len = payload_len >= payload_out_sz ? payload_out_sz - 1 : (size_t)payload_len;
	for (i = 0; i < copy_len; i++) {
		uint8_t byte = frame[pos + i];
		if (masked)
			byte ^= mask[i & 3];
		payload_out[i] = (char)byte;
	}
	payload_out[copy_len] = '\0';
	return (ssize_t)copy_len;
}
