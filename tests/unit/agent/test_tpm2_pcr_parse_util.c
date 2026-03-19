// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/tpm2_pcr_parse_util.h"

#include <string.h>

static void test_parse_pcr_bank_accepts_known_algorithms(void)
{
	uint16_t alg = 0;

	ELA_ASSERT_INT_EQ(0, ela_tpm2_parse_pcr_bank("sha256", &alg));
	ELA_ASSERT_INT_EQ(ELA_TPM2_ALG_SHA256, alg);
}

static void test_add_pcr_selection_sets_requested_bits(void)
{
	struct ela_tpm2_pcr_selection selection = {0};
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_tpm2_add_pcr_selection(&selection, "sha1:0,7,23", errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, selection.count);
	ELA_ASSERT_INT_EQ(ELA_TPM2_ALG_SHA1, selection.banks[0].hash_alg);
	ELA_ASSERT_TRUE((selection.banks[0].pcr_select[0] & 0x81) == 0x81);
	ELA_ASSERT_TRUE((selection.banks[0].pcr_select[2] & 0x80) == 0x80);
}

static void test_add_pcr_selection_rejects_duplicates_and_bad_input(void)
{
	struct ela_tpm2_pcr_selection selection = {0};
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_tpm2_add_pcr_selection(&selection, "sha256:1", errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(&selection, "sha256:2", errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "duplicate PCR bank") != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_tpm2_add_pcr_selection(&selection, "sha512:24", errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "invalid PCR index") != NULL);
}

int run_tpm2_pcr_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "parse_pcr_bank_accepts_known_algorithms", test_parse_pcr_bank_accepts_known_algorithms },
		{ "add_pcr_selection_sets_requested_bits", test_add_pcr_selection_sets_requested_bits },
		{ "add_pcr_selection_rejects_duplicates_and_bad_input", test_add_pcr_selection_rejects_duplicates_and_bad_input },
	};

	return ela_run_test_suite("tpm2_pcr_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
