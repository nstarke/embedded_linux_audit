// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/image/uboot_image_list_commands_util.h"

#include <stdint.h>
#include <string.h>

/* =========================================================================
 * ela_uboot_image_list_select_payload
 * ====================================================================== */

static void test_select_not_found_returns_full_blob(void)
{
	static const uint8_t blob[64];
	const uint8_t *payload = NULL;
	size_t plen = 0;

	ela_uboot_image_list_select_payload(blob, sizeof(blob),
					    false, 10,
					    &payload, &plen);
	ELA_ASSERT_TRUE(payload == blob);
	ELA_ASSERT_INT_EQ(64, (int)plen);
}

static void test_select_found_valid_offset(void)
{
	static const uint8_t blob[100];
	const uint8_t *payload = NULL;
	size_t plen = 0;

	ela_uboot_image_list_select_payload(blob, sizeof(blob),
					    true, 20,
					    &payload, &plen);
	ELA_ASSERT_TRUE(payload == blob + 20);
	ELA_ASSERT_INT_EQ(80, (int)plen);
}

static void test_select_found_zero_offset(void)
{
	static const uint8_t blob[64];
	const uint8_t *payload = NULL;
	size_t plen = 0;

	/* offset 0 is < blob_len, so payload starts at blob+0 */
	ela_uboot_image_list_select_payload(blob, sizeof(blob),
					    true, 0,
					    &payload, &plen);
	ELA_ASSERT_TRUE(payload == blob);
	ELA_ASSERT_INT_EQ(64, (int)plen);
}

static void test_select_found_offset_equals_len(void)
{
	static const uint8_t blob[64];
	const uint8_t *payload = NULL;
	size_t plen = 0;

	/* uboot_off == blob_len: not strictly less, falls back to full blob */
	ela_uboot_image_list_select_payload(blob, sizeof(blob),
					    true, 64,
					    &payload, &plen);
	ELA_ASSERT_TRUE(payload == blob);
	ELA_ASSERT_INT_EQ(64, (int)plen);
}

static void test_select_found_offset_exceeds_len(void)
{
	static const uint8_t blob[64];
	const uint8_t *payload = NULL;
	size_t plen = 0;

	ela_uboot_image_list_select_payload(blob, sizeof(blob),
					    true, 200,
					    &payload, &plen);
	ELA_ASSERT_TRUE(payload == blob);
	ELA_ASSERT_INT_EQ(64, (int)plen);
}

static void test_select_null_payload_out_no_crash(void)
{
	static const uint8_t blob[64];
	size_t plen = 42;

	/* null payload_out: function must not crash or write to plen */
	ela_uboot_image_list_select_payload(blob, sizeof(blob),
					    true, 10,
					    NULL, &plen);
	/* plen unchanged because we guard on both being non-NULL */
	ELA_ASSERT_INT_EQ(42, (int)plen);
}

static void test_select_null_payload_len_out_no_crash(void)
{
	static const uint8_t blob[64];
	const uint8_t *payload = (const uint8_t *)0xdeadbeef;

	ela_uboot_image_list_select_payload(blob, sizeof(blob),
					    true, 10,
					    &payload, NULL);
	/* payload unchanged because we guard on both being non-NULL */
	ELA_ASSERT_TRUE(payload == (const uint8_t *)0xdeadbeef);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_image_list_commands_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "select/not_found_full_blob",     test_select_not_found_returns_full_blob },
		{ "select/found_valid_offset",      test_select_found_valid_offset },
		{ "select/found_zero_offset",       test_select_found_zero_offset },
		{ "select/found_offset_eq_len",     test_select_found_offset_equals_len },
		{ "select/found_offset_exceeds",    test_select_found_offset_exceeds_len },
		{ "select/null_payload_out",        test_select_null_payload_out_no_crash },
		{ "select/null_payload_len_out",    test_select_null_payload_len_out_no_crash },
	};
	return ela_run_test_suite("uboot_image_list_commands_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
