// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/net/ws_frame_util.h"

#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * ela_ws_build_masked_frame
 * ---------------------------------------------------------------------- */

static void test_ws_frame_builder_and_parser_round_trip(void)
{
	const uint8_t mask[4] = { 0x12, 0x34, 0x56, 0x78 };
	uint8_t *frame = NULL;
	size_t frame_len = 0;
	uint8_t opcode = 0;
	char payload[64];

	ELA_ASSERT_INT_EQ(0, ela_ws_build_masked_frame(ELA_WS_OPCODE_TEXT, mask, "hello", 5, &frame, &frame_len));
	ELA_ASSERT_TRUE(frame_len > 6);
	ELA_ASSERT_INT_EQ(5, ela_ws_parse_frame_bytes(frame, frame_len, &opcode, payload, sizeof(payload)));
	ELA_ASSERT_INT_EQ(ELA_WS_OPCODE_TEXT, opcode);
	ELA_ASSERT_STR_EQ("hello", payload);
	free(frame);
}

static void test_ws_frame_build_rejects_null_mask(void)
{
	uint8_t *frame = NULL;
	size_t frame_len = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ws_build_masked_frame(ELA_WS_OPCODE_TEXT, NULL, "hi", 2, &frame, &frame_len));
}

static void test_ws_frame_build_rejects_null_frame_out(void)
{
	const uint8_t mask[4] = { 0, 0, 0, 0 };
	size_t frame_len = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ws_build_masked_frame(ELA_WS_OPCODE_TEXT, mask, "hi", 2, NULL, &frame_len));
}

static void test_ws_frame_build_rejects_null_frame_len_out(void)
{
	const uint8_t mask[4] = { 0, 0, 0, 0 };
	uint8_t *frame = NULL;

	ELA_ASSERT_INT_EQ(-1, ela_ws_build_masked_frame(ELA_WS_OPCODE_TEXT, mask, "hi", 2, &frame, NULL));
}

static void test_ws_frame_build_rejects_null_payload_with_nonzero_len(void)
{
	const uint8_t mask[4] = { 0, 0, 0, 0 };
	uint8_t *frame = NULL;
	size_t frame_len = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ws_build_masked_frame(ELA_WS_OPCODE_TEXT, mask, NULL, 5, &frame, &frame_len));
}

static void test_ws_frame_build_zero_payload_ping(void)
{
	const uint8_t mask[4] = { 0x11, 0x22, 0x33, 0x44 };
	uint8_t *frame = NULL;
	size_t frame_len = 0;
	uint8_t opcode = 0;
	char payload[8] = { 0 };

	/* NULL payload with 0 length is valid (e.g. PING) */
	ELA_ASSERT_INT_EQ(0, ela_ws_build_masked_frame(ELA_WS_OPCODE_PING, mask, NULL, 0, &frame, &frame_len));
	/* 2-byte header + 4-byte mask + 0-byte payload = 6 */
	ELA_ASSERT_INT_EQ(6, (int)frame_len);
	ELA_ASSERT_INT_EQ(0, ela_ws_parse_frame_bytes(frame, frame_len, &opcode, payload, sizeof(payload)));
	ELA_ASSERT_INT_EQ(ELA_WS_OPCODE_PING, opcode);
	free(frame);
}

static void test_ws_frame_build_extended_len_126_round_trip(void)
{
	const uint8_t mask[4] = { 0x01, 0x02, 0x03, 0x04 };
	char big_payload[200];
	uint8_t *frame = NULL;
	size_t frame_len = 0;
	uint8_t opcode = 0;
	char parsed[201];
	int i;

	for (i = 0; i < 200; i++)
		big_payload[i] = (char)('A' + (i % 26));

	ELA_ASSERT_INT_EQ(0, ela_ws_build_masked_frame(ELA_WS_OPCODE_TEXT, mask,
						       big_payload, 200,
						       &frame, &frame_len));
	/* 4-byte header (2 base + 2 ext) + 4-byte mask + 200-byte payload = 208 */
	ELA_ASSERT_INT_EQ(208, (int)frame_len);

	ELA_ASSERT_INT_EQ(200, ela_ws_parse_frame_bytes(frame, frame_len, &opcode, parsed, sizeof(parsed)));
	ELA_ASSERT_INT_EQ(ELA_WS_OPCODE_TEXT, opcode);
	ELA_ASSERT_INT_EQ(0, memcmp(big_payload, parsed, 200));
	free(frame);
}

/* -------------------------------------------------------------------------
 * ela_ws_parse_frame_bytes
 * ---------------------------------------------------------------------- */

static void test_ws_frame_parser_truncates_to_buffer(void)
{
	const uint8_t frame[] = { 0x81, 0x03, 'a', 'b', 'c' };
	uint8_t opcode = 0;
	char payload[3];

	ELA_ASSERT_INT_EQ(2, ela_ws_parse_frame_bytes(frame, sizeof(frame), &opcode, payload, sizeof(payload)));
	ELA_ASSERT_STR_EQ("ab", payload);
}

static void test_ws_frame_parse_rejects_null_frame(void)
{
	uint8_t opcode = 0;
	char buf[8];

	ELA_ASSERT_INT_EQ(-1, ela_ws_parse_frame_bytes(NULL, 5, &opcode, buf, sizeof(buf)));
}

static void test_ws_frame_parse_rejects_frame_too_short(void)
{
	const uint8_t frame[] = { 0x81 };
	uint8_t opcode = 0;
	char buf[8];

	ELA_ASSERT_INT_EQ(-1, ela_ws_parse_frame_bytes(frame, 1, &opcode, buf, sizeof(buf)));
}

static void test_ws_frame_parse_rejects_null_payload_out(void)
{
	const uint8_t frame[] = { 0x81, 0x00 };
	uint8_t opcode = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ws_parse_frame_bytes(frame, sizeof(frame), &opcode, NULL, 8));
}

static void test_ws_frame_parse_rejects_zero_payload_out_sz(void)
{
	const uint8_t frame[] = { 0x81, 0x00 };
	uint8_t opcode = 0;
	char buf[8];

	ELA_ASSERT_INT_EQ(-1, ela_ws_parse_frame_bytes(frame, sizeof(frame), &opcode, buf, 0));
}

static void test_ws_frame_parse_null_opcode_out_accepted(void)
{
	/* NULL opcode_out is allowed; payload is still extracted */
	const uint8_t frame[] = { 0x81, 0x02, 'h', 'i' };
	char buf[8];

	ELA_ASSERT_INT_EQ(2, ela_ws_parse_frame_bytes(frame, sizeof(frame), NULL, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("hi", buf);
}

static void test_ws_frame_parse_close_opcode(void)
{
	/* FIN=1, CLOSE opcode, no payload */
	const uint8_t frame[] = { 0x88, 0x00 };
	uint8_t opcode = 0;
	char buf[8];

	ELA_ASSERT_INT_EQ(0, ela_ws_parse_frame_bytes(frame, sizeof(frame), &opcode, buf, sizeof(buf)));
	ELA_ASSERT_INT_EQ(ELA_WS_OPCODE_CLOSE, opcode);
}

static void test_ws_frame_parse_masked_frame(void)
{
	/*
	 * "Hello" masked with key 0x37 0xfa 0x21 0x3d (RFC 6455 example).
	 * 0x48^0x37=0x7f, 0x65^0xfa=0x9f, 0x6c^0x21=0x4d, 0x6c^0x3d=0x51, 0x6f^0x37=0x58
	 */
	const uint8_t frame[] = {
		0x81, 0x85,
		0x37, 0xfa, 0x21, 0x3d,
		0x7f, 0x9f, 0x4d, 0x51, 0x58
	};
	uint8_t opcode = 0;
	char buf[16];

	ELA_ASSERT_INT_EQ(5, ela_ws_parse_frame_bytes(frame, sizeof(frame), &opcode, buf, sizeof(buf)));
	ELA_ASSERT_INT_EQ(ELA_WS_OPCODE_TEXT, opcode);
	ELA_ASSERT_STR_EQ("Hello", buf);
}

static void test_ws_frame_parse_extended_len_126(void)
{
	/* Manually construct a 126-byte-payload unmasked text frame */
	uint8_t frame[4 + 126];
	int i;
	uint8_t opcode = 0;
	char buf[200];

	frame[0] = 0x81;  /* FIN + TEXT */
	frame[1] = 126;   /* payload_len indicator = 126 → read 2 ext bytes */
	frame[2] = 0x00;
	frame[3] = 126;   /* actual length = 126 */
	for (i = 0; i < 126; i++)
		frame[4 + i] = (uint8_t)('a' + (i % 26));

	ELA_ASSERT_INT_EQ(126, ela_ws_parse_frame_bytes(frame, sizeof(frame), &opcode, buf, sizeof(buf)));
	ELA_ASSERT_INT_EQ(ELA_WS_OPCODE_TEXT, opcode);
	ELA_ASSERT_INT_EQ('a', (unsigned char)buf[0]);
	ELA_ASSERT_INT_EQ('b', (unsigned char)buf[1]);
}

static void test_ws_frame_parse_rejects_truncated_ext_len_126(void)
{
	/* Claims payload_len=126 but only has 1 ext byte, not 2 */
	const uint8_t frame[] = { 0x81, 126, 0x00 };
	uint8_t opcode = 0;
	char buf[16];

	ELA_ASSERT_INT_EQ(-1, ela_ws_parse_frame_bytes(frame, sizeof(frame), &opcode, buf, sizeof(buf)));
}

static void test_ws_frame_parse_rejects_truncated_mask(void)
{
	/* MASK bit set but only 3 mask bytes provided */
	const uint8_t frame[] = { 0x81, 0x85, 0x37, 0xfa, 0x21 }; /* 3 of 4 mask bytes */
	uint8_t opcode = 0;
	char buf[16];

	ELA_ASSERT_INT_EQ(-1, ela_ws_parse_frame_bytes(frame, sizeof(frame), &opcode, buf, sizeof(buf)));
}

static void test_ws_frame_parse_rejects_payload_beyond_frame(void)
{
	/* Header says 10 bytes but frame only has 4 */
	const uint8_t frame[] = { 0x81, 0x0A, 'a', 'b' };
	uint8_t opcode = 0;
	char buf[16];

	ELA_ASSERT_INT_EQ(-1, ela_ws_parse_frame_bytes(frame, sizeof(frame), &opcode, buf, sizeof(buf)));
}

int run_ws_frame_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "ws_frame_builder_and_parser_round_trip",         test_ws_frame_builder_and_parser_round_trip },
		{ "ws_frame_build_rejects_null_mask",               test_ws_frame_build_rejects_null_mask },
		{ "ws_frame_build_rejects_null_frame_out",          test_ws_frame_build_rejects_null_frame_out },
		{ "ws_frame_build_rejects_null_frame_len_out",      test_ws_frame_build_rejects_null_frame_len_out },
		{ "ws_frame_build_rejects_null_payload_with_len",   test_ws_frame_build_rejects_null_payload_with_nonzero_len },
		{ "ws_frame_build_zero_payload_ping",               test_ws_frame_build_zero_payload_ping },
		{ "ws_frame_build_extended_len_126_round_trip",     test_ws_frame_build_extended_len_126_round_trip },
		{ "ws_frame_parser_truncates_to_buffer",            test_ws_frame_parser_truncates_to_buffer },
		{ "ws_frame_parse_rejects_null_frame",              test_ws_frame_parse_rejects_null_frame },
		{ "ws_frame_parse_rejects_frame_too_short",         test_ws_frame_parse_rejects_frame_too_short },
		{ "ws_frame_parse_rejects_null_payload_out",        test_ws_frame_parse_rejects_null_payload_out },
		{ "ws_frame_parse_rejects_zero_payload_out_sz",     test_ws_frame_parse_rejects_zero_payload_out_sz },
		{ "ws_frame_parse_null_opcode_out_accepted",        test_ws_frame_parse_null_opcode_out_accepted },
		{ "ws_frame_parse_close_opcode",                    test_ws_frame_parse_close_opcode },
		{ "ws_frame_parse_masked_frame",                    test_ws_frame_parse_masked_frame },
		{ "ws_frame_parse_extended_len_126",                test_ws_frame_parse_extended_len_126 },
		{ "ws_frame_parse_rejects_truncated_ext_len_126",   test_ws_frame_parse_rejects_truncated_ext_len_126 },
		{ "ws_frame_parse_rejects_truncated_mask",          test_ws_frame_parse_rejects_truncated_mask },
		{ "ws_frame_parse_rejects_payload_beyond_frame",    test_ws_frame_parse_rejects_payload_beyond_frame },
	};

	return ela_run_test_suite("ws_frame_util", cases, sizeof(cases) / sizeof(cases[0]));
}
