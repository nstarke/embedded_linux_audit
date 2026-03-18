// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ws_interactive_util.h"

void ela_ws_default_mask_key(uint8_t mask[4])
{
	if (!mask)
		return;

	mask[0] = 0xDE;
	mask[1] = 0xAD;
	mask[2] = 0xBE;
	mask[3] = 0xEF;
}

bool ela_ws_socket_readable(int fd_ready, bool is_tls, int pending_bytes)
{
	if (fd_ready)
		return true;
	if (is_tls && pending_bytes > 0)
		return true;
	return false;
}
