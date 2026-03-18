// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/env/uboot_env_util.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

#include <stdlib.h>
#include <string.h>

static void test_uboot_env_set_unset_and_build_region(void)
{
	struct env_kv *kvs = NULL;
	size_t count = 0;
	uint8_t region[64];

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "bootcmd", "run boot"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "bootdelay", "3"));
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_set_kv(&kvs, &count, "bootdelay", "5"));
	ELA_ASSERT_INT_EQ(2, count);
	ELA_ASSERT_INT_EQ(0, ela_uboot_env_unset_kv(kvs, &count, "bootcmd"));
	ELA_ASSERT_INT_EQ(1, count);
	ELA_ASSERT_INT_EQ(0, ela_uboot_build_env_region(kvs, count, region, sizeof(region)));
	ELA_ASSERT_TRUE(memmem(region, sizeof(region), "bootdelay=5", 11) != NULL);
	ela_uboot_env_free_kvs(kvs, count);
}

static void test_uboot_parse_fw_config_line_and_existing_env_data(void)
{
	struct uboot_cfg_entry cfg;
	static const uint8_t envbuf[] = "bootcmd=run boot\0bootdelay=3\0\0";
	struct env_kv *kvs = NULL;
	size_t count = 0;

	ELA_ASSERT_INT_EQ(1, ela_uboot_parse_fw_config_line("/dev/mtd0 0x0 0x2000 0x2000 1", &cfg));
	ELA_ASSERT_STR_EQ("/dev/mtd0", cfg.dev);
	ELA_ASSERT_INT_EQ(0x2000, cfg.env_size);
	ELA_ASSERT_INT_EQ(0, ela_uboot_parse_existing_env_data(envbuf, sizeof(envbuf) - 1, 0, &kvs, &count));
	ELA_ASSERT_INT_EQ(2, count);
	ELA_ASSERT_STR_EQ("bootcmd", kvs[0].name);
	ELA_ASSERT_STR_EQ("3", kvs[1].value);
	ela_uboot_env_free_kvs(kvs, count);
}

static void test_uboot_env_crc_matches_detects_endianness(void)
{
	uint32_t table[256];
	uint8_t buf[16] = {0};
	uint32_t crc;
	bool is_le = false;

	ela_crc32_init(table);
	memcpy(buf + 4, "a=b\0\0", 5);
	crc = ela_crc32_calc(table, buf + 4, sizeof(buf) - 4);
	buf[0] = (uint8_t)crc;
	buf[1] = (uint8_t)(crc >> 8);
	buf[2] = (uint8_t)(crc >> 16);
	buf[3] = (uint8_t)(crc >> 24);
	ELA_ASSERT_TRUE(ela_uboot_env_crc_matches(table, buf, sizeof(buf), 4, &is_le));
	ELA_ASSERT_TRUE(is_le);
}

int run_uboot_env_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "uboot_env_set_unset_and_build_region", test_uboot_env_set_unset_and_build_region },
		{ "uboot_parse_fw_config_line_and_existing_env_data", test_uboot_parse_fw_config_line_and_existing_env_data },
		{ "uboot_env_crc_matches_detects_endianness", test_uboot_env_crc_matches_detects_endianness },
	};

	return ela_run_test_suite("uboot_env_util", cases, sizeof(cases) / sizeof(cases[0]));
}
