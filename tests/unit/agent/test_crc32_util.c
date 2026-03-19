// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

#include <stdint.h>
#include <string.h>

static void test_crc32_matches_standard_vector(void)
{
	uint32_t table[256];
	const char *payload = "123456789";

	ela_crc32_init(table);
	ELA_ASSERT_INT_EQ(0xCBF43926u, ela_crc32_calc(table, (const uint8_t *)payload, strlen(payload)));
}

static void test_crc32_rejects_null_inputs(void)
{
	uint32_t table[256];
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };

	ela_crc32_init(table);
	ELA_ASSERT_INT_EQ(0, ela_crc32_calc(NULL, payload, sizeof(payload)));
	ELA_ASSERT_INT_EQ(0, ela_crc32_calc(table, NULL, sizeof(payload)));
}

int run_crc32_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "crc32_matches_standard_vector", test_crc32_matches_standard_vector },
		{ "crc32_rejects_null_inputs", test_crc32_rejects_null_inputs },
	};

	return ela_run_test_suite("crc32_util", cases, sizeof(cases) / sizeof(cases[0]));
}
