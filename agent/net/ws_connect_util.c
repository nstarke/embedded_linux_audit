// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ws_connect_util.h"

#include <stdio.h>

void ela_ws_fill_nonce_from_seed(unsigned int seed, uint8_t nonce[16])
{
	size_t i;

	if (!nonce)
		return;

	for (i = 0; i < 16; i++) {
		seed = seed * 1664525u + 1013904223u;
		nonce[i] = (uint8_t)(seed >> 16);
	}
}

void ela_ws_format_mac_bytes(const uint8_t mac[6], char *buf, size_t buf_sz)
{
	if (!buf || buf_sz == 0)
		return;

	if (!mac) {
		snprintf(buf, buf_sz, "unknown");
		return;
	}

	snprintf(buf, buf_sz, "%02x-%02x-%02x-%02x-%02x-%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool ela_ws_mac_is_zero(const uint8_t mac[6])
{
	if (!mac)
		return true;

	return mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
	       mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
}
