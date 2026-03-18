// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ws_recv_util.h"

size_t ela_ws_payload_copy_len(uint64_t payload_len, size_t buf_sz)
{
	if (buf_sz == 0)
		return 0;
	if (payload_len >= buf_sz)
		return buf_sz - 1;
	return (size_t)payload_len;
}

size_t ela_ws_payload_skip_len(uint64_t payload_len, size_t buf_sz)
{
	size_t copy_len = ela_ws_payload_copy_len(payload_len, buf_sz);

	if (payload_len <= copy_len)
		return 0;
	return (size_t)(payload_len - copy_len);
}
