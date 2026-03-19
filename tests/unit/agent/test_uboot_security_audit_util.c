// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/uboot_security_audit_util.h"

#include <stdlib.h>
#include <string.h>

static void test_uboot_security_audit_output_and_rule_helpers(void)
{
	ELA_ASSERT_TRUE(ela_uboot_buffer_has_newline("a\nb", 3));
	ELA_ASSERT_FALSE(ela_uboot_buffer_has_newline("abc", 3));
	ELA_ASSERT_TRUE(ela_uboot_audit_rule_may_need_signature_artifacts(NULL));
	ELA_ASSERT_TRUE(ela_uboot_audit_rule_may_need_signature_artifacts("uboot_validate_secureboot"));
	ELA_ASSERT_FALSE(ela_uboot_audit_rule_may_need_signature_artifacts("other_rule"));
	ELA_ASSERT_INT_EQ(FW_OUTPUT_TXT, ela_uboot_audit_detect_output_format("txt"));
	ELA_ASSERT_INT_EQ(FW_OUTPUT_CSV, ela_uboot_audit_detect_output_format("csv"));
	ELA_ASSERT_INT_EQ(FW_OUTPUT_JSON, ela_uboot_audit_detect_output_format("json"));
}

static void test_uboot_fit_header_validation_helper(void)
{
	uint8_t hdr[64] = {0};

	hdr[0] = 0xD0; hdr[1] = 0x0D; hdr[2] = 0xFE; hdr[3] = 0xED;
	hdr[4] = 0x00; hdr[5] = 0x00; hdr[6] = 0x01; hdr[7] = 0x20;
	hdr[8] = 0x00; hdr[9] = 0x00; hdr[10] = 0x00; hdr[11] = 0x40;
	hdr[12] = 0x00; hdr[13] = 0x00; hdr[14] = 0x00; hdr[15] = 0xA0;
	hdr[16] = 0x00; hdr[17] = 0x00; hdr[18] = 0x00; hdr[19] = 0x28;
	hdr[20] = 0x00; hdr[21] = 0x00; hdr[22] = 0x00; hdr[23] = 0x11;
	hdr[24] = 0x00; hdr[25] = 0x00; hdr[26] = 0x00; hdr[27] = 0x10;
	hdr[32] = 0x00; hdr[33] = 0x00; hdr[34] = 0x00; hdr[35] = 0x20;
	hdr[36] = 0x00; hdr[37] = 0x00; hdr[38] = 0x00; hdr[39] = 0x40;

	ELA_ASSERT_TRUE(ela_uboot_fit_header_looks_valid(hdr, 0, 0x2000));
	hdr[35] = 0x00;
	ELA_ASSERT_FALSE(ela_uboot_fit_header_looks_valid(hdr, 0, 0x2000));
	ELA_ASSERT_TRUE(ela_uboot_read_be32(hdr) == 0xD00DFEEDu);
}

static void test_uboot_extract_public_key_pem_helper(void)
{
	const char *blob = "noise-----BEGIN PUBLIC KEY-----\nABCDEF\n-----END PUBLIC KEY-----tail";
	char *pem = NULL;

	ELA_ASSERT_INT_EQ(0, ela_uboot_extract_public_key_pem(blob, strlen(blob), &pem));
	ELA_ASSERT_STR_EQ("-----BEGIN PUBLIC KEY-----\nABCDEF\n-----END PUBLIC KEY-----\n", pem);
	free(pem);
	ELA_ASSERT_INT_EQ(-1, ela_uboot_extract_public_key_pem("-----BEGIN PUBLIC KEY-----", strlen("-----BEGIN PUBLIC KEY-----"), &pem));
}

int run_uboot_security_audit_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "uboot_security_audit_output_and_rule_helpers", test_uboot_security_audit_output_and_rule_helpers },
		{ "uboot_fit_header_validation_helper", test_uboot_fit_header_validation_helper },
		{ "uboot_extract_public_key_pem_helper", test_uboot_extract_public_key_pem_helper },
	};

	return ela_run_test_suite("uboot_security_audit_util", cases, sizeof(cases) / sizeof(cases[0]));
}
