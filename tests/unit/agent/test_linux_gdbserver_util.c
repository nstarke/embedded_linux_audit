// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/linux/linux_gdbserver_util.h"

#include <string.h>
#include <stdint.h>

/* =========================================================================
 * ela_gdb_rsp_checksum
 * ====================================================================== */

static void test_checksum_empty(void)
{
	ELA_ASSERT_INT_EQ(0, (int)ela_gdb_rsp_checksum("", 0));
}

static void test_checksum_null(void)
{
	ELA_ASSERT_INT_EQ(0, (int)ela_gdb_rsp_checksum(NULL, 0));
}

static void test_checksum_ok(void)
{
	/* 'O'=0x4f + 'K'=0x4b = 0x9a = 154 */
	ELA_ASSERT_INT_EQ(0x9a, (int)ela_gdb_rsp_checksum("OK", 2));
}

static void test_checksum_s05(void)
{
	/* 'S'=0x53 + '0'=0x30 + '5'=0x35 = 0xb8 = 184 */
	ELA_ASSERT_INT_EQ(0xb8, (int)ela_gdb_rsp_checksum("S05", 3));
}

static void test_checksum_wraps(void)
{
	/* All 0xff bytes: 3 × 255 = 765 mod 256 = 253 = 0xfd */
	uint8_t data[3] = { 0xff, 0xff, 0xff };

	ELA_ASSERT_INT_EQ(0xfd,
		(int)ela_gdb_rsp_checksum((const char *)data, 3));
}

/* =========================================================================
 * ela_gdb_rsp_frame
 * ====================================================================== */

static void test_frame_ok(void)
{
	char buf[16];

	ELA_ASSERT_INT_EQ(0, ela_gdb_rsp_frame("OK", 2, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("$OK#9a", buf);
}

static void test_frame_empty(void)
{
	char buf[8];

	ELA_ASSERT_INT_EQ(0, ela_gdb_rsp_frame("", 0, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("$#00", buf);
}

static void test_frame_s05(void)
{
	char buf[16];

	ELA_ASSERT_INT_EQ(0, ela_gdb_rsp_frame("S05", 3, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("$S05#b8", buf);
}

static void test_frame_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_gdb_rsp_frame("OK", 2, NULL, 16));
}

static void test_frame_buf_too_small(void)
{
	char buf[6]; /* need data_len + 5 = 7, only 6 available */

	ELA_ASSERT_INT_EQ(-1, ela_gdb_rsp_frame("OK", 2, buf, sizeof(buf)));
}

static void test_frame_exact_size(void)
{
	char buf[7]; /* $OK#9a\0 = 7 bytes */

	ELA_ASSERT_INT_EQ(0, ela_gdb_rsp_frame("OK", 2, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("$OK#9a", buf);
}

/* =========================================================================
 * ela_gdb_rsp_unframe
 * ====================================================================== */

static void test_unframe_ok(void)
{
	char out[16];
	int n;

	n = ela_gdb_rsp_unframe("$OK#9a", 6, out, sizeof(out));
	ELA_ASSERT_INT_EQ(2, n);
	ELA_ASSERT_STR_EQ("OK", out);
}

static void test_unframe_empty_payload(void)
{
	char out[8];
	int n;

	n = ela_gdb_rsp_unframe("$#00", 4, out, sizeof(out));
	ELA_ASSERT_INT_EQ(0, n);
	ELA_ASSERT_STR_EQ("", out);
}

static void test_unframe_bad_checksum(void)
{
	char out[16];

	ELA_ASSERT_INT_EQ(-1,
		ela_gdb_rsp_unframe("$OK#ff", 6, out, sizeof(out)));
}

static void test_unframe_no_dollar(void)
{
	char out[16];

	ELA_ASSERT_INT_EQ(-1,
		ela_gdb_rsp_unframe("OK#9a", 5, out, sizeof(out)));
}

static void test_unframe_too_short(void)
{
	char out[16];

	/* "$#x" — only 1 checksum char, need 2 */
	ELA_ASSERT_INT_EQ(-1,
		ela_gdb_rsp_unframe("$#9", 3, out, sizeof(out)));
}

static void test_unframe_null_pkt(void)
{
	char out[16];

	ELA_ASSERT_INT_EQ(-1,
		ela_gdb_rsp_unframe(NULL, 6, out, sizeof(out)));
}

static void test_unframe_uppercase_checksum(void)
{
	char out[16];
	int n;

	/* $OK#9A — uppercase checksum digits should be accepted */
	n = ela_gdb_rsp_unframe("$OK#9A", 6, out, sizeof(out));
	ELA_ASSERT_INT_EQ(2, n);
	ELA_ASSERT_STR_EQ("OK", out);
}

/* =========================================================================
 * ela_gdb_hex_encode
 * ====================================================================== */

static void test_hex_encode_bytes(void)
{
	uint8_t data[2] = { 0xde, 0xad };
	char out[8];

	ELA_ASSERT_INT_EQ(0, ela_gdb_hex_encode(data, 2, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("dead", out);
}

static void test_hex_encode_zero_len(void)
{
	char out[4] = "xxx";

	ELA_ASSERT_INT_EQ(0, ela_gdb_hex_encode(NULL, 0, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("", out);
}

static void test_hex_encode_null_out(void)
{
	uint8_t data[2] = { 0xde, 0xad };

	ELA_ASSERT_INT_EQ(-1, ela_gdb_hex_encode(data, 2, NULL, 0));
}

static void test_hex_encode_out_too_small(void)
{
	uint8_t data[2] = { 0xde, 0xad };
	char out[4]; /* need 5, only 4 */

	ELA_ASSERT_INT_EQ(-1, ela_gdb_hex_encode(data, 2, out, 4));
}

static void test_hex_encode_single_byte(void)
{
	uint8_t b = 0x0f;
	char out[4];

	ELA_ASSERT_INT_EQ(0, ela_gdb_hex_encode(&b, 1, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("0f", out);
}

/* =========================================================================
 * ela_gdb_hex_decode
 * ====================================================================== */

static void test_hex_decode_bytes(void)
{
	uint8_t out[4];
	int n;

	n = ela_gdb_hex_decode("dead", out, sizeof(out));
	ELA_ASSERT_INT_EQ(2, n);
	ELA_ASSERT_INT_EQ(0xde, (int)out[0]);
	ELA_ASSERT_INT_EQ(0xad, (int)out[1]);
}

static void test_hex_decode_empty(void)
{
	uint8_t out[4];

	ELA_ASSERT_INT_EQ(0, ela_gdb_hex_decode("", out, sizeof(out)));
}

static void test_hex_decode_odd_length(void)
{
	uint8_t out[4];

	ELA_ASSERT_INT_EQ(-1, ela_gdb_hex_decode("abc", out, sizeof(out)));
}

static void test_hex_decode_bad_chars(void)
{
	uint8_t out[4];

	ELA_ASSERT_INT_EQ(-1, ela_gdb_hex_decode("xyzw", out, sizeof(out)));
}

static void test_hex_decode_null(void)
{
	uint8_t out[4];

	ELA_ASSERT_INT_EQ(-1, ela_gdb_hex_decode(NULL, out, sizeof(out)));
}

static void test_hex_decode_uppercase(void)
{
	uint8_t out[4];
	int n;

	n = ela_gdb_hex_decode("DEAD", out, sizeof(out));
	ELA_ASSERT_INT_EQ(2, n);
	ELA_ASSERT_INT_EQ(0xde, (int)out[0]);
	ELA_ASSERT_INT_EQ(0xad, (int)out[1]);
}

/* =========================================================================
 * ela_gdb_rsp_ack
 * ====================================================================== */

static void test_ack_true(void)
{
	ELA_ASSERT_INT_EQ('+', (int)ela_gdb_rsp_ack(true));
}

static void test_ack_false(void)
{
	ELA_ASSERT_INT_EQ('-', (int)ela_gdb_rsp_ack(false));
}

/* =========================================================================
 * ela_gdb_encode_le64
 * ====================================================================== */

static void test_encode_le64_zero(void)
{
	char out[17];

	ELA_ASSERT_INT_EQ(0, ela_gdb_encode_le64(0, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("0000000000000000", out);
}

static void test_encode_le64_known_value(void)
{
	char out[17];

	/* 0x0102030405060708 → bytes 08 07 06 05 04 03 02 01 */
	ELA_ASSERT_INT_EQ(0,
		ela_gdb_encode_le64(UINT64_C(0x0102030405060708),
				    out, sizeof(out)));
	ELA_ASSERT_STR_EQ("0807060504030201", out);
}

static void test_encode_le64_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_gdb_encode_le64(0, NULL, 17));
}

static void test_encode_le64_buf_too_small(void)
{
	char out[16]; /* need 17 */

	ELA_ASSERT_INT_EQ(-1, ela_gdb_encode_le64(0, out, sizeof(out)));
}

/* =========================================================================
 * ela_gdb_encode_le32
 * ====================================================================== */

static void test_encode_le32_zero(void)
{
	char out[9];

	ELA_ASSERT_INT_EQ(0, ela_gdb_encode_le32(0, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("00000000", out);
}

static void test_encode_le32_known_value(void)
{
	char out[9];

	/* 0x01020304 → bytes 04 03 02 01 */
	ELA_ASSERT_INT_EQ(0, ela_gdb_encode_le32(0x01020304, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("04030201", out);
}

static void test_encode_le32_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_gdb_encode_le32(0, NULL, 9));
}

static void test_encode_le32_buf_too_small(void)
{
	char out[8]; /* need 9 */

	ELA_ASSERT_INT_EQ(-1, ela_gdb_encode_le32(0, out, sizeof(out)));
}

/* =========================================================================
 * ela_gdb_encode_be64
 * ====================================================================== */

static void test_encode_be64_zero(void)
{
	char out[17];

	ELA_ASSERT_INT_EQ(0, ela_gdb_encode_be64(0, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("0000000000000000", out);
}

static void test_encode_be64_known_value(void)
{
	char out[17];

	/* 0x0102030405060708 → bytes 01 02 03 04 05 06 07 08 */
	ELA_ASSERT_INT_EQ(0,
		ela_gdb_encode_be64(UINT64_C(0x0102030405060708),
				    out, sizeof(out)));
	ELA_ASSERT_STR_EQ("0102030405060708", out);
}

static void test_encode_be64_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_gdb_encode_be64(0, NULL, 17));
}

static void test_encode_be64_buf_too_small(void)
{
	char out[16]; /* need 17 */

	ELA_ASSERT_INT_EQ(-1, ela_gdb_encode_be64(0, out, sizeof(out)));
}

/* =========================================================================
 * ela_gdb_encode_be32
 * ====================================================================== */

static void test_encode_be32_zero(void)
{
	char out[9];

	ELA_ASSERT_INT_EQ(0, ela_gdb_encode_be32(0, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("00000000", out);
}

static void test_encode_be32_known_value(void)
{
	char out[9];

	/* 0x01020304 → bytes 01 02 03 04 */
	ELA_ASSERT_INT_EQ(0, ela_gdb_encode_be32(0x01020304, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("01020304", out);
}

static void test_encode_be32_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_gdb_encode_be32(0, NULL, 9));
}

static void test_encode_be32_buf_too_small(void)
{
	char out[8]; /* need 9 */

	ELA_ASSERT_INT_EQ(-1, ela_gdb_encode_be32(0, out, sizeof(out)));
}

/* =========================================================================
 * ela_gdb_decode_le32
 * ====================================================================== */

static void test_decode_le32_zero(void)
{
	uint32_t val = 99;

	ELA_ASSERT_INT_EQ(0, ela_gdb_decode_le32("00000000", &val));
	ELA_ASSERT_TRUE(val == 0);
}

static void test_decode_le32_known_value(void)
{
	uint32_t val = 0;

	/* "04030201" → bytes 04 03 02 01 (LE) → 0x01020304 */
	ELA_ASSERT_INT_EQ(0, ela_gdb_decode_le32("04030201", &val));
	ELA_ASSERT_TRUE(val == 0x01020304u);
}

static void test_decode_le32_null(void)
{
	uint32_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_decode_le32(NULL, &val));
}

static void test_decode_le32_wrong_length(void)
{
	uint32_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_decode_le32("0102", &val));
}

/* =========================================================================
 * ela_gdb_decode_le64
 * ====================================================================== */

static void test_decode_le64_zero(void)
{
	uint64_t val = 99;

	ELA_ASSERT_INT_EQ(0, ela_gdb_decode_le64("0000000000000000", &val));
	ELA_ASSERT_TRUE(val == 0);
}

static void test_decode_le64_known_value(void)
{
	uint64_t val = 0;

	/* "0807060504030201" → bytes 08..01 (LE) → 0x0102030405060708 */
	ELA_ASSERT_INT_EQ(0, ela_gdb_decode_le64("0807060504030201", &val));
	ELA_ASSERT_TRUE(val == UINT64_C(0x0102030405060708));
}

static void test_decode_le64_null(void)
{
	uint64_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_decode_le64(NULL, &val));
}

static void test_decode_le64_wrong_length(void)
{
	uint64_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_decode_le64("01020304", &val));
}

/* =========================================================================
 * ela_gdb_decode_be32
 * ====================================================================== */

static void test_decode_be32_zero(void)
{
	uint32_t val = 99;

	ELA_ASSERT_INT_EQ(0, ela_gdb_decode_be32("00000000", &val));
	ELA_ASSERT_TRUE(val == 0);
}

static void test_decode_be32_known_value(void)
{
	uint32_t val = 0;

	/* "01020304" → bytes 01 02 03 04 (BE) → 0x01020304 */
	ELA_ASSERT_INT_EQ(0, ela_gdb_decode_be32("01020304", &val));
	ELA_ASSERT_TRUE(val == 0x01020304u);
}

static void test_decode_be32_null(void)
{
	uint32_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_decode_be32(NULL, &val));
}

static void test_decode_be32_wrong_length(void)
{
	uint32_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_decode_be32("0102", &val));
}

/* =========================================================================
 * ela_gdb_decode_be64
 * ====================================================================== */

static void test_decode_be64_zero(void)
{
	uint64_t val = 99;

	ELA_ASSERT_INT_EQ(0, ela_gdb_decode_be64("0000000000000000", &val));
	ELA_ASSERT_TRUE(val == 0);
}

static void test_decode_be64_known_value(void)
{
	uint64_t val = 0;

	/* "0102030405060708" → bytes 01..08 (BE) → 0x0102030405060708 */
	ELA_ASSERT_INT_EQ(0, ela_gdb_decode_be64("0102030405060708", &val));
	ELA_ASSERT_TRUE(val == UINT64_C(0x0102030405060708));
}

static void test_decode_be64_null(void)
{
	uint64_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_decode_be64(NULL, &val));
}

static void test_decode_be64_wrong_length(void)
{
	uint64_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_decode_be64("01020304", &val));
}

/* =========================================================================
 * ela_gdb_parse_hex_u64
 * ====================================================================== */

static void test_parse_hex_u64_simple(void)
{
	uint64_t val = 0;

	ELA_ASSERT_INT_EQ(0, ela_gdb_parse_hex_u64("deadbeef", &val));
	ELA_ASSERT_TRUE(val == UINT64_C(0xdeadbeef));
}

static void test_parse_hex_u64_zero(void)
{
	uint64_t val = 99;

	ELA_ASSERT_INT_EQ(0, ela_gdb_parse_hex_u64("0", &val));
	ELA_ASSERT_TRUE(val == 0);
}

static void test_parse_hex_u64_max(void)
{
	uint64_t val = 0;

	ELA_ASSERT_INT_EQ(0,
		ela_gdb_parse_hex_u64("ffffffffffffffff", &val));
	ELA_ASSERT_TRUE(val == UINT64_MAX);
}

static void test_parse_hex_u64_mixed_case(void)
{
	uint64_t val = 0;

	ELA_ASSERT_INT_EQ(0, ela_gdb_parse_hex_u64("1a2B3c", &val));
	ELA_ASSERT_TRUE(val == UINT64_C(0x1a2b3c));
}

static void test_parse_hex_u64_empty(void)
{
	uint64_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_parse_hex_u64("", &val));
}

static void test_parse_hex_u64_null(void)
{
	uint64_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_parse_hex_u64(NULL, &val));
}

static void test_parse_hex_u64_bad_chars(void)
{
	uint64_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_parse_hex_u64("xyz", &val));
}

static void test_parse_hex_u64_trailing_garbage(void)
{
	uint64_t val = 0;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_parse_hex_u64("1234xyz", &val));
}

/* =========================================================================
 * Round-trip: frame then unframe
 * ====================================================================== */

static void test_roundtrip_arbitrary_payload(void)
{
	const char *payload = "qSupported:multiprocess+";
	char framed[64];
	char recovered[64];
	int n;

	ELA_ASSERT_INT_EQ(0,
		ela_gdb_rsp_frame(payload, strlen(payload),
				  framed, sizeof(framed)));
	n = ela_gdb_rsp_unframe(framed, strlen(framed),
				recovered, sizeof(recovered));
	ELA_ASSERT_INT_EQ((int)strlen(payload), n);
	ELA_ASSERT_STR_EQ(payload, recovered);
}

/* =========================================================================
 * Test suite registration
 * ====================================================================== */

int run_linux_gdbserver_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "checksum/empty",              test_checksum_empty },
		{ "checksum/null",               test_checksum_null },
		{ "checksum/ok",                 test_checksum_ok },
		{ "checksum/s05",                test_checksum_s05 },
		{ "checksum/wraps",              test_checksum_wraps },
		{ "frame/ok",                    test_frame_ok },
		{ "frame/empty",                 test_frame_empty },
		{ "frame/s05",                   test_frame_s05 },
		{ "frame/null_out",              test_frame_null_out },
		{ "frame/buf_too_small",         test_frame_buf_too_small },
		{ "frame/exact_size",            test_frame_exact_size },
		{ "unframe/ok",                  test_unframe_ok },
		{ "unframe/empty_payload",       test_unframe_empty_payload },
		{ "unframe/bad_checksum",        test_unframe_bad_checksum },
		{ "unframe/no_dollar",           test_unframe_no_dollar },
		{ "unframe/too_short",           test_unframe_too_short },
		{ "unframe/null_pkt",            test_unframe_null_pkt },
		{ "unframe/uppercase_checksum",  test_unframe_uppercase_checksum },
		{ "hex_encode/bytes",            test_hex_encode_bytes },
		{ "hex_encode/zero_len",         test_hex_encode_zero_len },
		{ "hex_encode/null_out",         test_hex_encode_null_out },
		{ "hex_encode/out_too_small",    test_hex_encode_out_too_small },
		{ "hex_encode/single_byte",      test_hex_encode_single_byte },
		{ "hex_decode/bytes",            test_hex_decode_bytes },
		{ "hex_decode/empty",            test_hex_decode_empty },
		{ "hex_decode/odd_length",       test_hex_decode_odd_length },
		{ "hex_decode/bad_chars",        test_hex_decode_bad_chars },
		{ "hex_decode/null",             test_hex_decode_null },
		{ "hex_decode/uppercase",        test_hex_decode_uppercase },
		{ "ack/true",                    test_ack_true },
		{ "ack/false",                   test_ack_false },
		{ "encode_le64/zero",            test_encode_le64_zero },
		{ "encode_le64/known_value",     test_encode_le64_known_value },
		{ "encode_le64/null_out",        test_encode_le64_null_out },
		{ "encode_le64/buf_too_small",   test_encode_le64_buf_too_small },
		{ "encode_le32/zero",            test_encode_le32_zero },
		{ "encode_le32/known_value",     test_encode_le32_known_value },
		{ "encode_le32/null_out",        test_encode_le32_null_out },
		{ "encode_le32/buf_too_small",   test_encode_le32_buf_too_small },
		{ "encode_be64/zero",            test_encode_be64_zero },
		{ "encode_be64/known_value",     test_encode_be64_known_value },
		{ "encode_be64/null_out",        test_encode_be64_null_out },
		{ "encode_be64/buf_too_small",   test_encode_be64_buf_too_small },
		{ "encode_be32/zero",            test_encode_be32_zero },
		{ "encode_be32/known_value",     test_encode_be32_known_value },
		{ "encode_be32/null_out",        test_encode_be32_null_out },
		{ "encode_be32/buf_too_small",   test_encode_be32_buf_too_small },
		{ "decode_le32/zero",            test_decode_le32_zero },
		{ "decode_le32/known_value",     test_decode_le32_known_value },
		{ "decode_le32/null",            test_decode_le32_null },
		{ "decode_le32/wrong_length",    test_decode_le32_wrong_length },
		{ "decode_le64/zero",            test_decode_le64_zero },
		{ "decode_le64/known_value",     test_decode_le64_known_value },
		{ "decode_le64/null",            test_decode_le64_null },
		{ "decode_le64/wrong_length",    test_decode_le64_wrong_length },
		{ "decode_be32/zero",            test_decode_be32_zero },
		{ "decode_be32/known_value",     test_decode_be32_known_value },
		{ "decode_be32/null",            test_decode_be32_null },
		{ "decode_be32/wrong_length",    test_decode_be32_wrong_length },
		{ "decode_be64/zero",            test_decode_be64_zero },
		{ "decode_be64/known_value",     test_decode_be64_known_value },
		{ "decode_be64/null",            test_decode_be64_null },
		{ "decode_be64/wrong_length",    test_decode_be64_wrong_length },
		{ "parse_hex_u64/simple",        test_parse_hex_u64_simple },
		{ "parse_hex_u64/zero",          test_parse_hex_u64_zero },
		{ "parse_hex_u64/max",           test_parse_hex_u64_max },
		{ "parse_hex_u64/mixed_case",    test_parse_hex_u64_mixed_case },
		{ "parse_hex_u64/empty",         test_parse_hex_u64_empty },
		{ "parse_hex_u64/null",          test_parse_hex_u64_null },
		{ "parse_hex_u64/bad_chars",     test_parse_hex_u64_bad_chars },
		{ "parse_hex_u64/trailing_junk", test_parse_hex_u64_trailing_garbage },
		{ "roundtrip/arbitrary_payload", test_roundtrip_arbitrary_payload },
	};

	return ela_run_test_suite("linux_gdbserver_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
