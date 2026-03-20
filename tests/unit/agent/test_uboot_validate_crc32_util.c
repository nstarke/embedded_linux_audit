// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/audit-rules/uboot_validate_crc32_util.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

#include <stdint.h>
#include <string.h>

/* =========================================================================
 * Helpers to build a valid env block with a LE CRC32
 * ====================================================================== */

static void build_le_env(uint8_t *buf, size_t buf_len, uint32_t *table)
{
	uint32_t crc;

	memset(buf, 0, buf_len);
	memcpy(buf + 4, "k=v\0\0", 5);
	crc = ela_crc32_calc(table, buf + 4, buf_len - 4);
	buf[0] = (uint8_t)crc;
	buf[1] = (uint8_t)(crc >> 8);
	buf[2] = (uint8_t)(crc >> 16);
	buf[3] = (uint8_t)(crc >> 24);
}

static void build_be_env(uint8_t *buf, size_t buf_len, uint32_t *table)
{
	uint32_t crc;

	memset(buf, 0, buf_len);
	memcpy(buf + 4, "k=v\0\0", 5);
	crc = ela_crc32_calc(table, buf + 4, buf_len - 4);
	buf[0] = (uint8_t)(crc >> 24);
	buf[1] = (uint8_t)(crc >> 16);
	buf[2] = (uint8_t)(crc >> 8);
	buf[3] = (uint8_t)crc;
}

/* =========================================================================
 * ela_uboot_validate_crc32_cmp — null / size guard
 * ====================================================================== */

static void test_null_input(void)
{
	char msg[64];

	ELA_ASSERT_INT_EQ(-1, ela_uboot_validate_crc32_cmp(NULL, msg, sizeof(msg)));
}

static void test_null_data(void)
{
	uint32_t table[256];
	struct embedded_linux_audit_input input = {0};
	char msg[64];

	ela_crc32_init(table);
	input.crc32_table = table;
	input.data = NULL;
	input.data_len = 32;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_validate_crc32_cmp(&input, msg, sizeof(msg)));
}

static void test_null_crc32_table(void)
{
	uint8_t buf[32] = {0};
	struct embedded_linux_audit_input input = {0};
	char msg[64];

	input.data = buf;
	input.data_len = sizeof(buf);
	input.crc32_table = NULL;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_validate_crc32_cmp(&input, msg, sizeof(msg)));
}

static void test_too_small(void)
{
	uint32_t table[256];
	uint8_t buf[7] = {0};
	struct embedded_linux_audit_input input = {0};
	char msg[64];

	ela_crc32_init(table);
	input.data = buf;
	input.data_len = sizeof(buf);
	input.crc32_table = table;
	ELA_ASSERT_INT_EQ(-1, ela_uboot_validate_crc32_cmp(&input, msg, sizeof(msg)));
}

static void test_exactly_8_bytes_mismatch(void)
{
	uint32_t table[256];
	uint8_t buf[8] = {0};
	struct embedded_linux_audit_input input = {0};
	char msg[128];

	ela_crc32_init(table);
	/* CRC fields are all zero but calculated CRC will not be zero */
	input.data = buf;
	input.data_len = sizeof(buf);
	input.crc32_table = table;
	ELA_ASSERT_INT_EQ(1, ela_uboot_validate_crc32_cmp(&input, msg, sizeof(msg)));
}

/* =========================================================================
 * ela_uboot_validate_crc32_cmp — valid matches
 * ====================================================================== */

static void test_valid_le_match(void)
{
	uint32_t table[256];
	uint8_t buf[32];
	struct embedded_linux_audit_input input = {0};
	char msg[128];

	ela_crc32_init(table);
	build_le_env(buf, sizeof(buf), table);
	input.data = buf;
	input.data_len = sizeof(buf);
	input.crc32_table = table;
	ELA_ASSERT_INT_EQ(0, ela_uboot_validate_crc32_cmp(&input, msg, sizeof(msg)));
}

static void test_valid_le_match_message(void)
{
	uint32_t table[256];
	uint8_t buf[32];
	struct embedded_linux_audit_input input = {0};
	char msg[256];

	ela_crc32_init(table);
	build_le_env(buf, sizeof(buf), table);
	input.data = buf;
	input.data_len = sizeof(buf);
	input.crc32_table = table;
	ela_uboot_validate_crc32_cmp(&input, msg, sizeof(msg));
	ELA_ASSERT_TRUE(strstr(msg, "LE") != NULL);
	ELA_ASSERT_TRUE(strstr(msg, "standard") != NULL);
}

static void test_valid_be_match(void)
{
	uint32_t table[256];
	uint8_t buf[32];
	struct embedded_linux_audit_input input = {0};
	char msg[128];

	ela_crc32_init(table);
	build_be_env(buf, sizeof(buf), table);
	input.data = buf;
	input.data_len = sizeof(buf);
	input.crc32_table = table;
	ELA_ASSERT_INT_EQ(0, ela_uboot_validate_crc32_cmp(&input, msg, sizeof(msg)));
}

static void test_valid_be_match_message(void)
{
	uint32_t table[256];
	uint8_t buf[32];
	struct embedded_linux_audit_input input = {0};
	char msg[256];

	ela_crc32_init(table);
	build_be_env(buf, sizeof(buf), table);
	input.data = buf;
	input.data_len = sizeof(buf);
	input.crc32_table = table;
	ela_uboot_validate_crc32_cmp(&input, msg, sizeof(msg));
	ELA_ASSERT_TRUE(strstr(msg, "BE") != NULL);
}

static void test_redundant_le_match(void)
{
	uint32_t table[256];
	uint8_t buf[32];
	uint32_t redund_crc;
	struct embedded_linux_audit_input input = {0};
	char msg[256];

	ela_crc32_init(table);
	memset(buf, 0, sizeof(buf));
	memcpy(buf + 5, "k=v\0\0", 5);
	/* Standard CRC (data+4) will mismatch; redundant (data+5) stored LE */
	redund_crc = ela_crc32_calc(table, buf + 5, sizeof(buf) - 5);
	buf[0] = (uint8_t)redund_crc;
	buf[1] = (uint8_t)(redund_crc >> 8);
	buf[2] = (uint8_t)(redund_crc >> 16);
	buf[3] = (uint8_t)(redund_crc >> 24);
	/* Ensure standard CRC does NOT match by corrupting byte 4 */
	buf[4] = 0xFF;
	input.data = buf;
	input.data_len = sizeof(buf);
	input.crc32_table = table;
	ELA_ASSERT_INT_EQ(0, ela_uboot_validate_crc32_cmp(&input, msg, sizeof(msg)));
	ELA_ASSERT_TRUE(strstr(msg, "redundant") != NULL);
}

static void test_mismatch_message(void)
{
	uint32_t table[256];
	uint8_t buf[32] = {0};
	struct embedded_linux_audit_input input = {0};
	char msg[256];

	ela_crc32_init(table);
	input.data = buf;
	input.data_len = sizeof(buf);
	input.crc32_table = table;
	ela_uboot_validate_crc32_cmp(&input, msg, sizeof(msg));
	ELA_ASSERT_TRUE(strstr(msg, "mismatch") != NULL);
}

static void test_null_message_ok(void)
{
	uint32_t table[256];
	uint8_t buf[32];
	struct embedded_linux_audit_input input = {0};

	ela_crc32_init(table);
	build_le_env(buf, sizeof(buf), table);
	input.data = buf;
	input.data_len = sizeof(buf);
	input.crc32_table = table;
	ELA_ASSERT_INT_EQ(0, ela_uboot_validate_crc32_cmp(&input, NULL, 0));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_validate_crc32_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "null_input",             test_null_input },
		{ "null_data",              test_null_data },
		{ "null_crc32_table",       test_null_crc32_table },
		{ "too_small",              test_too_small },
		{ "exactly_8_mismatch",     test_exactly_8_bytes_mismatch },
		{ "valid_le_match",         test_valid_le_match },
		{ "valid_le_match_message", test_valid_le_match_message },
		{ "valid_be_match",         test_valid_be_match },
		{ "valid_be_match_message", test_valid_be_match_message },
		{ "redundant_le_match",     test_redundant_le_match },
		{ "mismatch_message",       test_mismatch_message },
		{ "null_message_ok",        test_null_message_ok },
	};
	return ela_run_test_suite("uboot_validate_crc32_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
