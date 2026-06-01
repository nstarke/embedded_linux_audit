// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"

int run_tpm2_util_tests(void);

#if defined(ELA_HAS_TPM2)

#include "../../../agent/tpm2/tpm2_internal.h"

#include <stdint.h>

/* -----------------------------------------------------------------------
 * Link-only stubs for the libtss2 entry points referenced by tpm2_open()/
 * tpm2_close().  Those wrappers require a real /dev/tpm0 and are excluded
 * from coverage (LCOV_EXCL); the unit tests below never call them, so these
 * stubs exist purely to satisfy the linker without pulling in libtss2.
 * --------------------------------------------------------------------- */

TSS2_RC Tss2_Tcti_Device_Init(TSS2_TCTI_CONTEXT *tctiContext, size_t *size,
			      const char *conf)
{
	(void)tctiContext;
	(void)conf;
	if (size)
		*size = 0;
	return 1;
}

TSS2_RC Esys_Initialize(ESYS_CONTEXT **esys_context, TSS2_TCTI_CONTEXT *tcti,
			TSS2_ABI_VERSION *abiVersion)
{
	(void)tcti;
	(void)abiVersion;
	if (esys_context)
		*esys_context = NULL;
	return 1;
}

void Esys_Finalize(ESYS_CONTEXT **context)
{
	(void)context;
}

/* -----------------------------------------------------------------------
 * tpm2_rc_to_exit_code
 * --------------------------------------------------------------------- */

static void test_rc_success_is_zero(void)
{
	ELA_ASSERT_INT_EQ(0, tpm2_rc_to_exit_code(TPM2_RC_SUCCESS));
}

static void test_rc_nonzero_is_one(void)
{
	ELA_ASSERT_INT_EQ(1, tpm2_rc_to_exit_code(TPM2_RC_FAILURE));
	ELA_ASSERT_INT_EQ(1, tpm2_rc_to_exit_code(0x12345));
}

/* -----------------------------------------------------------------------
 * parse_u32 (delegates to ela_parse_u32: base-0 parse, 0 ok / -1 fail)
 * --------------------------------------------------------------------- */

static void test_parse_u32_decimal(void)
{
	uint32_t v = 0;

	ELA_ASSERT_INT_EQ(0, parse_u32("42", &v));
	ELA_ASSERT_TRUE(v == 42u);
}

static void test_parse_u32_max(void)
{
	uint32_t v = 0;

	ELA_ASSERT_INT_EQ(0, parse_u32("4294967295", &v));
	ELA_ASSERT_TRUE(v == 4294967295u);
}

static void test_parse_u32_hex(void)
{
	uint32_t v = 0;

	/* base 0 honours the 0x prefix */
	ELA_ASSERT_INT_EQ(0, parse_u32("0x10", &v));
	ELA_ASSERT_TRUE(v == 16u);
}

static void test_parse_u32_rejects_garbage(void)
{
	uint32_t v = 0;

	ELA_ASSERT_INT_EQ(-1, parse_u32("notanumber", &v));
	ELA_ASSERT_INT_EQ(-1, parse_u32("", &v));
	ELA_ASSERT_INT_EQ(-1, parse_u32(NULL, &v));
}

static void test_parse_u32_rejects_overflow(void)
{
	uint32_t v = 0;

	ELA_ASSERT_INT_EQ(-1, parse_u32("4294967296", &v));
}

/* -----------------------------------------------------------------------
 * parse_hash_alg (delegates to ela_tpm2_parse_pcr_bank)
 * --------------------------------------------------------------------- */

static void test_parse_hash_alg_known_banks(void)
{
	ELA_ASSERT_INT_EQ((int)TPM2_ALG_SHA1,   (int)parse_hash_alg("sha1"));
	ELA_ASSERT_INT_EQ((int)TPM2_ALG_SHA256, (int)parse_hash_alg("sha256"));
	ELA_ASSERT_INT_EQ((int)TPM2_ALG_SHA384, (int)parse_hash_alg("sha384"));
	ELA_ASSERT_INT_EQ((int)TPM2_ALG_SHA512, (int)parse_hash_alg("sha512"));
}

static void test_parse_hash_alg_unknown_is_error(void)
{
	ELA_ASSERT_INT_EQ((int)TPM2_ALG_ERROR, (int)parse_hash_alg("md5"));
	ELA_ASSERT_INT_EQ((int)TPM2_ALG_ERROR, (int)parse_hash_alg(""));
	ELA_ASSERT_INT_EQ((int)TPM2_ALG_ERROR, (int)parse_hash_alg("sha"));
}

int run_tpm2_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "rc/success_is_zero",        test_rc_success_is_zero },
		{ "rc/nonzero_is_one",         test_rc_nonzero_is_one },
		{ "parse_u32/decimal",         test_parse_u32_decimal },
		{ "parse_u32/max",             test_parse_u32_max },
		{ "parse_u32/hex",             test_parse_u32_hex },
		{ "parse_u32/garbage",         test_parse_u32_rejects_garbage },
		{ "parse_u32/overflow",        test_parse_u32_rejects_overflow },
		{ "parse_hash_alg/known",      test_parse_hash_alg_known_banks },
		{ "parse_hash_alg/unknown",    test_parse_hash_alg_unknown_is_error },
	};

	return ela_run_test_suite("tpm2_util", cases, sizeof(cases) / sizeof(cases[0]));
}

#else /* !ELA_HAS_TPM2 */

int run_tpm2_util_tests(void)
{
	return 0;
}

#endif /* ELA_HAS_TPM2 */
