// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ws_connect_util.h"

#include <string.h>

static void test_ws_connect_nonce_from_seed_is_deterministic(void)
{
	uint8_t nonce_a[16];
	uint8_t nonce_b[16];

	ela_ws_fill_nonce_from_seed(1234u, nonce_a);
	ela_ws_fill_nonce_from_seed(1234u, nonce_b);
	ELA_ASSERT_TRUE(memcmp(nonce_a, nonce_b, sizeof(nonce_a)) == 0);
	ELA_ASSERT_TRUE(nonce_a[0] != 0 || nonce_a[1] != 0);
}

static void test_ws_connect_mac_helpers(void)
{
	static const uint8_t zero_mac[6] = {0};
	static const uint8_t mac[6] = {0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc};
	char text[32];

	ELA_ASSERT_TRUE(ela_ws_mac_is_zero(zero_mac));
	ELA_ASSERT_FALSE(ela_ws_mac_is_zero(mac));
	ela_ws_format_mac_bytes(mac, text, sizeof(text));
	ELA_ASSERT_STR_EQ("00-11-22-aa-bb-cc", text);
}

int run_ws_connect_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "ws_connect_nonce_from_seed_is_deterministic", test_ws_connect_nonce_from_seed_is_deterministic },
		{ "ws_connect_mac_helpers", test_ws_connect_mac_helpers },
	};

	return ela_run_test_suite("ws_connect_util", cases, sizeof(cases) / sizeof(cases[0]));
}
