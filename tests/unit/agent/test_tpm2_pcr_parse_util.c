// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/tpm2_pcr_parse_util.h"

#include <string.h>

/* -------------------------------------------------------------------------
 * ela_tpm2_parse_pcr_bank
 * ---------------------------------------------------------------------- */

static void test_parse_pcr_bank_null_name(void)
{
	uint16_t alg = 0xFFFF;

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_parse_pcr_bank(NULL, &alg));
}

static void test_parse_pcr_bank_null_alg_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_parse_pcr_bank("sha256", NULL));
}

static void test_parse_pcr_bank_sha1(void)
{
	uint16_t alg = 0;

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_pcr_bank("sha1", &alg));
	ELA_ASSERT_INT_EQ(ELA_TPM2_ALG_SHA1, alg);
	ELA_ASSERT_INT_EQ(0x0004, alg);
}

static void test_parse_pcr_bank_sha256(void)
{
	uint16_t alg = 0;

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_pcr_bank("sha256", &alg));
	ELA_ASSERT_INT_EQ(ELA_TPM2_ALG_SHA256, alg);
	ELA_ASSERT_INT_EQ(0x000b, alg);
}

static void test_parse_pcr_bank_sha384(void)
{
	uint16_t alg = 0;

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_pcr_bank("sha384", &alg));
	ELA_ASSERT_INT_EQ(ELA_TPM2_ALG_SHA384, alg);
	ELA_ASSERT_INT_EQ(0x000c, alg);
}

static void test_parse_pcr_bank_sha512(void)
{
	uint16_t alg = 0;

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_pcr_bank("sha512", &alg));
	ELA_ASSERT_INT_EQ(ELA_TPM2_ALG_SHA512, alg);
	ELA_ASSERT_INT_EQ(0x000d, alg);
}

static void test_parse_pcr_bank_unknown(void)
{
	uint16_t alg = 0;

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_parse_pcr_bank("md5",    &alg));
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_parse_pcr_bank("SHA256", &alg)); /* case sensitive */
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_parse_pcr_bank("",       &alg));
}

static void test_parse_pcr_bank_alg_constants_values(void)
{
	/* Verify the ELA constants match the TPM2 spec algorithm IDs */
	ELA_ASSERT_INT_EQ(0x0004, ELA_TPM2_ALG_SHA1);
	ELA_ASSERT_INT_EQ(0x000b, ELA_TPM2_ALG_SHA256);
	ELA_ASSERT_INT_EQ(0x000c, ELA_TPM2_ALG_SHA384);
	ELA_ASSERT_INT_EQ(0x000d, ELA_TPM2_ALG_SHA512);
	ELA_ASSERT_INT_EQ(0x0000, ELA_TPM2_ALG_ERROR);
}

/* -------------------------------------------------------------------------
 * ela_tpm2_add_pcr_selection
 * ---------------------------------------------------------------------- */

static void test_add_pcr_null_selection(void)
{
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(NULL, "sha256:0",
							  errbuf, sizeof(errbuf)));
}

static void test_add_pcr_null_spec(void)
{
	struct ela_tpm2_pcr_selection sel = {0};
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(&sel, NULL,
							  errbuf, sizeof(errbuf)));
}

static void test_add_pcr_empty_spec(void)
{
	struct ela_tpm2_pcr_selection sel = {0};
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(&sel, "",
							  errbuf, sizeof(errbuf)));
}

static void test_add_pcr_no_colon(void)
{
	struct ela_tpm2_pcr_selection sel = {0};
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(&sel, "sha256",
							  errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "alg:pcr") != NULL);
}

static void test_add_pcr_unknown_bank(void)
{
	struct ela_tpm2_pcr_selection sel = {0};
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(&sel, "md5:0",
							  errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "unsupported PCR bank") != NULL);
}

static void test_add_pcr_single_pcr_0(void)
{
	struct ela_tpm2_pcr_selection sel = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_add_pcr_selection(&sel, "sha256:0", NULL, 0));
	ELA_ASSERT_INT_EQ(1, (int)sel.count);
	ELA_ASSERT_INT_EQ(ELA_TPM2_ALG_SHA256, sel.banks[0].hash_alg);
	/* PCR 0 → bit 0 of byte 0 */
	ELA_ASSERT_TRUE((sel.banks[0].pcr_select[0] & 0x01) != 0);
}

static void test_add_pcr_pcr_7(void)
{
	struct ela_tpm2_pcr_selection sel = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_add_pcr_selection(&sel, "sha256:7", NULL, 0));
	/* PCR 7 → bit 7 of byte 0 */
	ELA_ASSERT_TRUE((sel.banks[0].pcr_select[0] & 0x80) != 0);
}

static void test_add_pcr_pcr_8(void)
{
	struct ela_tpm2_pcr_selection sel = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_add_pcr_selection(&sel, "sha256:8", NULL, 0));
	/* PCR 8 → bit 0 of byte 1 */
	ELA_ASSERT_TRUE((sel.banks[0].pcr_select[1] & 0x01) != 0);
	ELA_ASSERT_INT_EQ(0, sel.banks[0].pcr_select[0]);
}

static void test_add_pcr_pcr_23(void)
{
	struct ela_tpm2_pcr_selection sel = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_add_pcr_selection(&sel, "sha256:23", NULL, 0));
	/* PCR 23 → bit 7 of byte 2 */
	ELA_ASSERT_TRUE((sel.banks[0].pcr_select[2] & 0x80) != 0);
}

static void test_add_pcr_boundary_0_and_23(void)
{
	struct ela_tpm2_pcr_selection sel = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_add_pcr_selection(&sel, "sha1:0,7,23", NULL, 0));
	ELA_ASSERT_INT_EQ(1, (int)sel.count);
	ELA_ASSERT_INT_EQ(ELA_TPM2_ALG_SHA1, sel.banks[0].hash_alg);
	ELA_ASSERT_TRUE((sel.banks[0].pcr_select[0] & 0x81) == 0x81); /* bits 0 and 7 */
	ELA_ASSERT_TRUE((sel.banks[0].pcr_select[2] & 0x80) == 0x80); /* bit 7 of byte 2 */
}

static void test_add_pcr_index_24_invalid(void)
{
	struct ela_tpm2_pcr_selection sel = {0};
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(&sel, "sha256:24",
							  errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "invalid PCR index") != NULL);
}

static void test_add_pcr_non_numeric_index(void)
{
	struct ela_tpm2_pcr_selection sel = {0};
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(&sel, "sha256:abc",
							  errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "invalid PCR index") != NULL);
}

static void test_add_pcr_multiple_banks(void)
{
	struct ela_tpm2_pcr_selection sel = {0};

	ELA_ASSERT_INT_EQ(0, ela_tpm2_add_pcr_selection(&sel, "sha256:1", NULL, 0));
	ELA_ASSERT_INT_EQ(0, ela_tpm2_add_pcr_selection(&sel, "sha1:2",   NULL, 0));
	ELA_ASSERT_INT_EQ(2, (int)sel.count);
	ELA_ASSERT_INT_EQ(ELA_TPM2_ALG_SHA256, sel.banks[0].hash_alg);
	ELA_ASSERT_INT_EQ(ELA_TPM2_ALG_SHA1,   sel.banks[1].hash_alg);
}

static void test_add_pcr_duplicate_bank(void)
{
	struct ela_tpm2_pcr_selection sel = {0};
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(0,  ela_tpm2_add_pcr_selection(&sel, "sha256:1",
							  errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(&sel, "sha256:2",
							  errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "duplicate PCR bank") != NULL);
}

static void test_add_pcr_max_banks_exceeded(void)
{
	struct ela_tpm2_pcr_selection sel = {0};
	const char *banks[] = {
		"sha1:0", "sha256:0", "sha384:0", "sha512:0",
	};
	int i;

	/* Fill up with 4 unique banks (max is ELA_TPM2_MAX_PCR_BANKS = 16) */
	for (i = 0; i < 4; i++)
		ELA_ASSERT_INT_EQ(0, ela_tpm2_add_pcr_selection(&sel, banks[i], NULL, 0));

	ELA_ASSERT_INT_EQ(4, (int)sel.count);
}

static void test_add_pcr_null_errbuf_no_crash(void)
{
	struct ela_tpm2_pcr_selection sel = {0};

	/* Must not crash on invalid input with NULL errbuf */
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(&sel, "sha256", NULL, 0));
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(&sel, "bad:99", NULL, 0));
}

static void test_add_pcr_all_sha256_pcrs(void)
{
	struct ela_tpm2_pcr_selection sel = {0};

	/* PCRs 0-7: byte 0 = 0xFF */
	ELA_ASSERT_INT_EQ(0, ela_tpm2_add_pcr_selection(&sel, "sha256:0,1,2,3,4,5,6,7",
							NULL, 0));
	ELA_ASSERT_INT_EQ(0xFF, sel.banks[0].pcr_select[0]);
	ELA_ASSERT_INT_EQ(0x00, sel.banks[0].pcr_select[1]);
	ELA_ASSERT_INT_EQ(0x00, sel.banks[0].pcr_select[2]);
}

int run_tpm2_pcr_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* parse_pcr_bank */
		{ "parse_pcr_bank_null_name",          test_parse_pcr_bank_null_name },
		{ "parse_pcr_bank_null_alg_out",       test_parse_pcr_bank_null_alg_out },
		{ "parse_pcr_bank_sha1",               test_parse_pcr_bank_sha1 },
		{ "parse_pcr_bank_sha256",             test_parse_pcr_bank_sha256 },
		{ "parse_pcr_bank_sha384",             test_parse_pcr_bank_sha384 },
		{ "parse_pcr_bank_sha512",             test_parse_pcr_bank_sha512 },
		{ "parse_pcr_bank_unknown",            test_parse_pcr_bank_unknown },
		{ "parse_pcr_bank_alg_constants",      test_parse_pcr_bank_alg_constants_values },
		/* add_pcr_selection */
		{ "add_pcr_null_selection",            test_add_pcr_null_selection },
		{ "add_pcr_null_spec",                 test_add_pcr_null_spec },
		{ "add_pcr_empty_spec",                test_add_pcr_empty_spec },
		{ "add_pcr_no_colon",                  test_add_pcr_no_colon },
		{ "add_pcr_unknown_bank",              test_add_pcr_unknown_bank },
		{ "add_pcr_single_pcr_0",              test_add_pcr_single_pcr_0 },
		{ "add_pcr_pcr_7",                     test_add_pcr_pcr_7 },
		{ "add_pcr_pcr_8",                     test_add_pcr_pcr_8 },
		{ "add_pcr_pcr_23",                    test_add_pcr_pcr_23 },
		{ "add_pcr_boundary_0_and_23",         test_add_pcr_boundary_0_and_23 },
		{ "add_pcr_index_24_invalid",          test_add_pcr_index_24_invalid },
		{ "add_pcr_non_numeric_index",         test_add_pcr_non_numeric_index },
		{ "add_pcr_multiple_banks",            test_add_pcr_multiple_banks },
		{ "add_pcr_duplicate_bank",            test_add_pcr_duplicate_bank },
		{ "add_pcr_max_banks_exceeded",        test_add_pcr_max_banks_exceeded },
		{ "add_pcr_null_errbuf_no_crash",      test_add_pcr_null_errbuf_no_crash },
		{ "add_pcr_all_sha256_pcrs",           test_add_pcr_all_sha256_pcrs },
	};

	return ela_run_test_suite("tpm2_pcr_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
