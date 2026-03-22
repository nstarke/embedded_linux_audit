// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/linux/linux_gdbserver_tunnel_util.h"

#include <stdint.h>
#include <string.h>

/* =========================================================================
 * ela_gdb_tunnel_format_hex_key
 * ====================================================================== */

static void test_format_hex_key_basic(void)
{
	uint8_t raw[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	char out[33];

	ela_gdb_tunnel_format_hex_key(raw, sizeof(raw), out);
	ELA_ASSERT_STR_EQ("00112233445566778899aabbccddeeff", out);
}

static void test_format_hex_key_all_zero(void)
{
	uint8_t raw[16] = { 0 };
	char    out[33];

	ela_gdb_tunnel_format_hex_key(raw, sizeof(raw), out);
	ELA_ASSERT_STR_EQ("00000000000000000000000000000000", out);
}

static void test_format_hex_key_all_ff(void)
{
	uint8_t raw[16];
	char    out[33];

	memset(raw, 0xff, sizeof(raw));
	ela_gdb_tunnel_format_hex_key(raw, sizeof(raw), out);
	ELA_ASSERT_STR_EQ("ffffffffffffffffffffffffffffffff", out);
}

static void test_format_hex_key_single_byte(void)
{
	uint8_t raw[1] = { 0x0a };
	char    out[3];

	ela_gdb_tunnel_format_hex_key(raw, sizeof(raw), out);
	ELA_ASSERT_STR_EQ("0a", out);
}

static void test_format_hex_key_nul_terminated(void)
{
	uint8_t raw[2] = { 0xab, 0xcd };
	char    out[5];

	memset(out, 0xff, sizeof(out));
	ela_gdb_tunnel_format_hex_key(raw, sizeof(raw), out);
	ELA_ASSERT_INT_EQ(0, (int)(unsigned char)out[4]);
}

/* =========================================================================
 * ela_gdb_tunnel_build_urls
 * ====================================================================== */

static void test_build_urls_basic(void)
{
	char in_url[256], out_url[256];
	int  rc;

	rc = ela_gdb_tunnel_build_urls(
		"wss://host", "aabbccddeeff00112233445566778899",
		in_url, sizeof(in_url), out_url, sizeof(out_url));

	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ(
		"wss://host/gdb/in/aabbccddeeff00112233445566778899",  in_url);
	ELA_ASSERT_STR_EQ(
		"wss://host/gdb/out/aabbccddeeff00112233445566778899", out_url);
}

static void test_build_urls_strips_one_slash(void)
{
	char in_url[256], out_url[256];
	int  rc;

	rc = ela_gdb_tunnel_build_urls(
		"wss://host/", "aabbccddeeff00112233445566778899",
		in_url, sizeof(in_url), out_url, sizeof(out_url));

	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ(
		"wss://host/gdb/in/aabbccddeeff00112233445566778899",  in_url);
	ELA_ASSERT_STR_EQ(
		"wss://host/gdb/out/aabbccddeeff00112233445566778899", out_url);
}

static void test_build_urls_strips_multiple_slashes(void)
{
	char in_url[256], out_url[256];
	int  rc;

	rc = ela_gdb_tunnel_build_urls(
		"wss://host///", "aabbccddeeff00112233445566778899",
		in_url, sizeof(in_url), out_url, sizeof(out_url));

	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ(
		"wss://host/gdb/in/aabbccddeeff00112233445566778899",  in_url);
	ELA_ASSERT_STR_EQ(
		"wss://host/gdb/out/aabbccddeeff00112233445566778899", out_url);
}

static void test_build_urls_with_port(void)
{
	char in_url[256], out_url[256];
	int  rc;

	rc = ela_gdb_tunnel_build_urls(
		"wss://host:9000", "aabbccddeeff00112233445566778899",
		in_url, sizeof(in_url), out_url, sizeof(out_url));

	ELA_ASSERT_INT_EQ(0, rc);
	ELA_ASSERT_STR_EQ(
		"wss://host:9000/gdb/in/aabbccddeeff00112233445566778899",  in_url);
	ELA_ASSERT_STR_EQ(
		"wss://host:9000/gdb/out/aabbccddeeff00112233445566778899", out_url);
}

static void test_build_urls_in_too_small(void)
{
	char in_url[10], out_url[256];
	int  rc;

	rc = ela_gdb_tunnel_build_urls(
		"wss://host", "aabbccddeeff00112233445566778899",
		in_url, sizeof(in_url), out_url, sizeof(out_url));

	ELA_ASSERT_INT_EQ(-1, rc);
}

static void test_build_urls_out_too_small(void)
{
	char in_url[256], out_url[10];
	int  rc;

	rc = ela_gdb_tunnel_build_urls(
		"wss://host", "aabbccddeeff00112233445566778899",
		in_url, sizeof(in_url), out_url, sizeof(out_url));

	ELA_ASSERT_INT_EQ(-1, rc);
}

/* =========================================================================
 * ela_gdb_tunnel_key_is_valid
 * ====================================================================== */

static void test_key_valid_basic(void)
{
	ELA_ASSERT_INT_EQ(1,
		ela_gdb_tunnel_key_is_valid("aabbccddeeff00112233445566778899"));
}

static void test_key_valid_all_zero(void)
{
	ELA_ASSERT_INT_EQ(1,
		ela_gdb_tunnel_key_is_valid("00000000000000000000000000000000"));
}

static void test_key_valid_all_f(void)
{
	ELA_ASSERT_INT_EQ(1,
		ela_gdb_tunnel_key_is_valid("ffffffffffffffffffffffffffffffff"));
}

static void test_key_invalid_null(void)
{
	ELA_ASSERT_INT_EQ(0, ela_gdb_tunnel_key_is_valid(NULL));
}

static void test_key_invalid_empty(void)
{
	ELA_ASSERT_INT_EQ(0, ela_gdb_tunnel_key_is_valid(""));
}

static void test_key_invalid_too_short(void)
{
	ELA_ASSERT_INT_EQ(0, ela_gdb_tunnel_key_is_valid("aabbccdd"));
}

static void test_key_invalid_too_long(void)
{
	ELA_ASSERT_INT_EQ(0,
		ela_gdb_tunnel_key_is_valid("aabbccddeeff001122334455667788990"));
}

static void test_key_invalid_uppercase(void)
{
	ELA_ASSERT_INT_EQ(0,
		ela_gdb_tunnel_key_is_valid("AABBCCDDEEFF00112233445566778899"));
}

static void test_key_invalid_non_hex(void)
{
	ELA_ASSERT_INT_EQ(0,
		ela_gdb_tunnel_key_is_valid("aabbccddeeff001122334455667788zz"));
}

static void test_key_invalid_g_char(void)
{
	ELA_ASSERT_INT_EQ(0,
		ela_gdb_tunnel_key_is_valid("aabbccddeeff001122334455667788gg"));
}

/* =========================================================================
 * Test suite registration
 * ====================================================================== */

int run_linux_gdbserver_tunnel_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "format_hex_key/basic",          test_format_hex_key_basic },
		{ "format_hex_key/all_zero",       test_format_hex_key_all_zero },
		{ "format_hex_key/all_ff",         test_format_hex_key_all_ff },
		{ "format_hex_key/single_byte",    test_format_hex_key_single_byte },
		{ "format_hex_key/nul_terminated", test_format_hex_key_nul_terminated },
		{ "build_urls/basic",              test_build_urls_basic },
		{ "build_urls/strips_one_slash",   test_build_urls_strips_one_slash },
		{ "build_urls/strips_many_slashes",test_build_urls_strips_multiple_slashes },
		{ "build_urls/with_port",          test_build_urls_with_port },
		{ "build_urls/in_too_small",       test_build_urls_in_too_small },
		{ "build_urls/out_too_small",      test_build_urls_out_too_small },
		{ "key_is_valid/basic",            test_key_valid_basic },
		{ "key_is_valid/all_zero",         test_key_valid_all_zero },
		{ "key_is_valid/all_f",            test_key_valid_all_f },
		{ "key_is_valid/null",             test_key_invalid_null },
		{ "key_is_valid/empty",            test_key_invalid_empty },
		{ "key_is_valid/too_short",        test_key_invalid_too_short },
		{ "key_is_valid/too_long",         test_key_invalid_too_long },
		{ "key_is_valid/uppercase",        test_key_invalid_uppercase },
		{ "key_is_valid/non_hex",          test_key_invalid_non_hex },
		{ "key_is_valid/g_char",           test_key_invalid_g_char },
	};

	return ela_run_test_suite("linux_gdbserver_tunnel_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
