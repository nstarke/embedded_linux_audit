// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/audit-rules/uboot_audit_util.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

#include <stdlib.h>
#include <string.h>

static void test_uboot_audit_value_and_signature_helpers(void)
{
	uint8_t *out = NULL;
	size_t out_len = 0;

	ELA_ASSERT_TRUE(ela_uboot_value_is_enabled("enabled"));
	ELA_ASSERT_TRUE(ela_uboot_value_is_disabled(""));
	ELA_ASSERT_TRUE(ela_uboot_value_is_nonempty("x"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_decode_hex_signature("0x41:42-43", &out, &out_len));
	ELA_ASSERT_INT_EQ(3, out_len);
	ELA_ASSERT_INT_EQ('A', out[0]);
	free(out);
	out = NULL;
	ELA_ASSERT_INT_EQ(0, ela_uboot_decode_base64_signature("QUJD", &out, &out_len));
	ELA_ASSERT_INT_EQ(3, out_len);
	ELA_ASSERT_INT_EQ('C', out[2]);
	free(out);
}

static void test_uboot_audit_env_helpers_parse_and_find_values(void)
{
	struct env_kv_view pairs[8];
	static const uint8_t envbuf[] = "bootcmd=dhcp\0bootargs=console=ttyS0 init=/bin/sh\0\0";
	int count;
	char init_value[64];

	count = ela_uboot_parse_env_pairs(envbuf, sizeof(envbuf) - 1, 0, pairs, 8);
	ELA_ASSERT_INT_EQ(2, count);
	ELA_ASSERT_STR_EQ("dhcp", ela_uboot_find_env_value(pairs, (size_t)count, "bootcmd"));
	ELA_ASSERT_TRUE(ela_uboot_value_suggests_network_boot("run dhcp"));
	ELA_ASSERT_TRUE(ela_uboot_value_suggests_factory_reset("factory_reset"));
	ELA_ASSERT_TRUE(ela_uboot_parse_init_parameter("console=ttyS0 init=/bin/sh quiet", init_value, sizeof(init_value)));
	ELA_ASSERT_STR_EQ("/bin/sh", init_value);
	ELA_ASSERT_TRUE(ela_uboot_init_path_looks_valid("/sbin/init"));
}

static void test_uboot_choose_env_data_offset_and_parse_int(void)
{
	uint32_t table[256];
	uint8_t buf[32] = {0};
	uint32_t crc;
	size_t data_off = 0;
	struct embedded_linux_audit_input input = {0};
	int value = 0;

	ela_crc32_init(table);
	memcpy(buf + 4, "x=y\0\0", 5);
	crc = ela_crc32_calc(table, buf + 4, sizeof(buf) - 4);
	buf[0] = (uint8_t)crc;
	buf[1] = (uint8_t)(crc >> 8);
	buf[2] = (uint8_t)(crc >> 16);
	buf[3] = (uint8_t)(crc >> 24);
	input.data = buf;
	input.data_len = sizeof(buf);
	input.crc32_table = table;
	ELA_ASSERT_INT_EQ(0, ela_uboot_choose_env_data_offset(&input, &data_off));
	ELA_ASSERT_INT_EQ(4, data_off);
	ELA_ASSERT_INT_EQ(0, ela_uboot_parse_int_value("-5", &value));
	ELA_ASSERT_INT_EQ(-5, value);
}

int run_uboot_audit_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "uboot_audit_value_and_signature_helpers", test_uboot_audit_value_and_signature_helpers },
		{ "uboot_audit_env_helpers_parse_and_find_values", test_uboot_audit_env_helpers_parse_and_find_values },
		{ "uboot_choose_env_data_offset_and_parse_int", test_uboot_choose_env_data_offset_and_parse_int },
	};

	return ela_run_test_suite("uboot_audit_util", cases, sizeof(cases) / sizeof(cases[0]));
}
