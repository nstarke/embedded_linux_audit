// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

#include <stdint.h>
#include <string.h>

/* =========================================================================
 * ela_crc32_init
 * ====================================================================== */

static void test_crc32_init_null_no_crash(void)
{
	ela_crc32_init(NULL); /* must not crash */
	ELA_ASSERT_TRUE(1);
}

static void test_crc32_init_produces_known_table_entry(void)
{
	uint32_t table[256];

	ela_crc32_init(table);
	/* Table entry 1 for standard CRC-32 (polynomial 0xEDB88320) is 0x77073096 */
	ELA_ASSERT_INT_EQ((int)0x77073096u, (int)table[1]);
}

/* =========================================================================
 * ela_crc32_calc
 * ====================================================================== */

static void test_crc32_rejects_null_inputs(void)
{
	uint32_t table[256];
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };

	ela_crc32_init(table);
	ELA_ASSERT_INT_EQ(0, (int)ela_crc32_calc(NULL, payload, sizeof(payload)));
	ELA_ASSERT_INT_EQ(0, (int)ela_crc32_calc(table, NULL, sizeof(payload)));
}

static void test_crc32_empty_buffer_returns_zero(void)
{
	uint32_t table[256];

	ela_crc32_init(table);
	/* No bytes processed: 0xFFFFFFFF ^ 0xFFFFFFFF = 0 */
	ELA_ASSERT_INT_EQ(0, (int)ela_crc32_calc(table, (const uint8_t *)"", 0));
}

static void test_crc32_matches_standard_vector(void)
{
	uint32_t table[256];
	const char *payload = "123456789";

	ela_crc32_init(table);
	ELA_ASSERT_INT_EQ((int)0xCBF43926u,
			  (int)ela_crc32_calc(table, (const uint8_t *)payload, strlen(payload)));
}

static void test_crc32_matches_abc_vector(void)
{
	uint32_t table[256];
	const char *payload = "abc";

	ela_crc32_init(table);
	/* CRC-32 of "abc" = 0x352441C2 */
	ELA_ASSERT_INT_EQ((int)0x352441C2u,
			  (int)ela_crc32_calc(table, (const uint8_t *)payload, strlen(payload)));
}

static void test_crc32_single_zero_byte(void)
{
	uint32_t table[256];
	const uint8_t payload[] = { 0x00 };

	ela_crc32_init(table);
	/* CRC-32 of a single 0x00 byte = 0xD202EF8D */
	ELA_ASSERT_INT_EQ((int)0xD202EF8Du,
			  (int)ela_crc32_calc(table, payload, 1));
}

static void test_crc32_same_data_twice_same_result(void)
{
	uint32_t table[256];
	const char *payload = "hello";
	uint32_t r1, r2;

	ela_crc32_init(table);
	r1 = ela_crc32_calc(table, (const uint8_t *)payload, strlen(payload));
	r2 = ela_crc32_calc(table, (const uint8_t *)payload, strlen(payload));
	ELA_ASSERT_INT_EQ((int)r1, (int)r2);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_crc32_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "init/null_no_crash",              test_crc32_init_null_no_crash },
		{ "init/known_table_entry",          test_crc32_init_produces_known_table_entry },
		{ "calc/null_inputs",                test_crc32_rejects_null_inputs },
		{ "calc/empty_buffer",               test_crc32_empty_buffer_returns_zero },
		{ "calc/standard_vector_123456789",  test_crc32_matches_standard_vector },
		{ "calc/abc_vector",                 test_crc32_matches_abc_vector },
		{ "calc/single_zero_byte",           test_crc32_single_zero_byte },
		{ "calc/same_data_deterministic",    test_crc32_same_data_twice_same_result },
	};

	return ela_run_test_suite("crc32_util", cases, sizeof(cases) / sizeof(cases[0]));
}
