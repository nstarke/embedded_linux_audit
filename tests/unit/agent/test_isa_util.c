// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/isa_util.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

/* =========================================================================
 * normalize_isa_name
 * ====================================================================== */

static void test_normalize_null_returns_null(void)
{
	ELA_ASSERT_TRUE(normalize_isa_name(NULL) == NULL);
}

static void test_normalize_empty_returns_null(void)
{
	ELA_ASSERT_TRUE(normalize_isa_name("") == NULL);
}

static void test_normalize_x86_variants(void)
{
	ELA_ASSERT_STR_EQ(ELA_ISA_X86, normalize_isa_name("x86"));
	ELA_ASSERT_STR_EQ(ELA_ISA_X86, normalize_isa_name("i386"));
	ELA_ASSERT_STR_EQ(ELA_ISA_X86, normalize_isa_name("i486"));
	ELA_ASSERT_STR_EQ(ELA_ISA_X86, normalize_isa_name("i586"));
	ELA_ASSERT_STR_EQ(ELA_ISA_X86, normalize_isa_name("i686"));
}

static void test_normalize_x86_64_variants(void)
{
	ELA_ASSERT_STR_EQ(ELA_ISA_X86_64, normalize_isa_name("x86_64"));
	ELA_ASSERT_STR_EQ(ELA_ISA_X86_64, normalize_isa_name("amd64"));
}

static void test_normalize_aarch64_le_variants(void)
{
	ELA_ASSERT_STR_EQ(ELA_ISA_AARCH64_LE, normalize_isa_name("aarch64"));
	ELA_ASSERT_STR_EQ(ELA_ISA_AARCH64_LE, normalize_isa_name("arm64"));
	ELA_ASSERT_STR_EQ(ELA_ISA_AARCH64_LE, normalize_isa_name("aarch64le"));
	ELA_ASSERT_STR_EQ(ELA_ISA_AARCH64_LE, normalize_isa_name("aarch64-le"));
}

static void test_normalize_aarch64_be_variants(void)
{
	ELA_ASSERT_STR_EQ(ELA_ISA_AARCH64_BE, normalize_isa_name("aarch64_be"));
	ELA_ASSERT_STR_EQ(ELA_ISA_AARCH64_BE, normalize_isa_name("aarch64be"));
	ELA_ASSERT_STR_EQ(ELA_ISA_AARCH64_BE, normalize_isa_name("aarch64-be"));
}

static void test_normalize_preserves_unknown_values(void)
{
	ELA_ASSERT_STR_EQ("powerpc", normalize_isa_name("powerpc"));
	ELA_ASSERT_STR_EQ("mips",    normalize_isa_name("mips"));
	ELA_ASSERT_STR_EQ("riscv64", normalize_isa_name("riscv64"));
}

/* =========================================================================
 * isa_is_powerpc_family
 * ====================================================================== */

static void test_powerpc_family_all_variants(void)
{
	ELA_ASSERT_TRUE(isa_is_powerpc_family("powerpc"));
	ELA_ASSERT_TRUE(isa_is_powerpc_family("ppc"));
	ELA_ASSERT_TRUE(isa_is_powerpc_family("powerpc64"));
	ELA_ASSERT_TRUE(isa_is_powerpc_family("ppc64"));
	ELA_ASSERT_TRUE(isa_is_powerpc_family("powerpc64le"));
	ELA_ASSERT_TRUE(isa_is_powerpc_family("ppc64le"));
}

static void test_powerpc_family_null_and_non_powerpc_return_false(void)
{
	ELA_ASSERT_FALSE(isa_is_powerpc_family(NULL));
	ELA_ASSERT_FALSE(isa_is_powerpc_family(""));
	ELA_ASSERT_FALSE(isa_is_powerpc_family("x86_64"));
	ELA_ASSERT_FALSE(isa_is_powerpc_family("aarch64"));
	ELA_ASSERT_FALSE(isa_is_powerpc_family("mips"));
}

/* =========================================================================
 * isa_is_arm32_family
 * ====================================================================== */

static void test_arm32_family_qemu_canonical_names(void)
{
	ELA_ASSERT_TRUE(isa_is_arm32_family("arm32-le"));
	ELA_ASSERT_TRUE(isa_is_arm32_family("arm32-be"));
}

static void test_arm32_family_real_hardware_uname_strings(void)
{
	/* Common strings returned by uname(2) on real 32-bit ARM hardware */
	ELA_ASSERT_TRUE(isa_is_arm32_family("armv7l"));
	ELA_ASSERT_TRUE(isa_is_arm32_family("armv6l"));
	ELA_ASSERT_TRUE(isa_is_arm32_family("armv5tel"));
	ELA_ASSERT_TRUE(isa_is_arm32_family("armv5tl"));
	ELA_ASSERT_TRUE(isa_is_arm32_family("arm"));
}

static void test_arm32_family_aarch64_not_matched(void)
{
	/* 64-bit ARM must NOT be treated as arm32 */
	ELA_ASSERT_FALSE(isa_is_arm32_family("aarch64"));
	ELA_ASSERT_FALSE(isa_is_arm32_family("aarch64-le"));
	ELA_ASSERT_FALSE(isa_is_arm32_family("aarch64-be"));
	ELA_ASSERT_FALSE(isa_is_arm32_family("aarch64le"));
	ELA_ASSERT_FALSE(isa_is_arm32_family("aarch64be"));
}

static void test_arm32_family_non_arm_not_matched(void)
{
	ELA_ASSERT_FALSE(isa_is_arm32_family("x86_64"));
	ELA_ASSERT_FALSE(isa_is_arm32_family("x86"));
	ELA_ASSERT_FALSE(isa_is_arm32_family("powerpc"));
	ELA_ASSERT_FALSE(isa_is_arm32_family("mips"));
	ELA_ASSERT_FALSE(isa_is_arm32_family("riscv32"));
}

static void test_arm32_family_null_returns_false(void)
{
	ELA_ASSERT_FALSE(isa_is_arm32_family(NULL));
}

/* =========================================================================
 * ela_isa_supported_for_efi_bios
 * ====================================================================== */

static void test_efi_bios_null_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_isa_supported_for_efi_bios(NULL));
}

static void test_efi_bios_empty_returns_false(void)
{
	ELA_ASSERT_FALSE(ela_isa_supported_for_efi_bios(""));
}

static void test_efi_bios_x86_family_supported(void)
{
	ELA_ASSERT_TRUE(ela_isa_supported_for_efi_bios("x86"));
	ELA_ASSERT_TRUE(ela_isa_supported_for_efi_bios("i686"));   /* normalises to x86 */
	ELA_ASSERT_TRUE(ela_isa_supported_for_efi_bios("x86_64"));
	ELA_ASSERT_TRUE(ela_isa_supported_for_efi_bios("amd64"));  /* normalises to x86_64 */
}

static void test_efi_bios_aarch64_family_supported(void)
{
	ELA_ASSERT_TRUE(ela_isa_supported_for_efi_bios("aarch64-be"));
	ELA_ASSERT_TRUE(ela_isa_supported_for_efi_bios("aarch64-le"));
	ELA_ASSERT_TRUE(ela_isa_supported_for_efi_bios("arm64"));  /* normalises to aarch64-le */
	ELA_ASSERT_TRUE(ela_isa_supported_for_efi_bios("aarch64")); /* normalises to aarch64-le */
}

static void test_efi_bios_non_supported_return_false(void)
{
	ELA_ASSERT_FALSE(ela_isa_supported_for_efi_bios("powerpc"));
	ELA_ASSERT_FALSE(ela_isa_supported_for_efi_bios("ppc64"));
	ELA_ASSERT_FALSE(ela_isa_supported_for_efi_bios("mips"));
	ELA_ASSERT_FALSE(ela_isa_supported_for_efi_bios("riscv64"));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_isa_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* normalize_isa_name */
		{ "normalize/null",               test_normalize_null_returns_null },
		{ "normalize/empty",              test_normalize_empty_returns_null },
		{ "normalize/x86_variants",       test_normalize_x86_variants },
		{ "normalize/x86_64_variants",    test_normalize_x86_64_variants },
		{ "normalize/aarch64_le",         test_normalize_aarch64_le_variants },
		{ "normalize/aarch64_be",         test_normalize_aarch64_be_variants },
		{ "normalize/unknown_passthrough", test_normalize_preserves_unknown_values },
		/* isa_is_powerpc_family */
		{ "powerpc/all_variants",         test_powerpc_family_all_variants },
		{ "powerpc/null_and_non_powerpc", test_powerpc_family_null_and_non_powerpc_return_false },
		/* isa_is_arm32_family */
		{ "arm32/qemu_canonical_names",       test_arm32_family_qemu_canonical_names },
		{ "arm32/real_hardware_uname_strings", test_arm32_family_real_hardware_uname_strings },
		{ "arm32/aarch64_not_matched",        test_arm32_family_aarch64_not_matched },
		{ "arm32/non_arm_not_matched",        test_arm32_family_non_arm_not_matched },
		{ "arm32/null_returns_false",         test_arm32_family_null_returns_false },
		/* ela_isa_supported_for_efi_bios */
		{ "efi_bios/null",                test_efi_bios_null_returns_false },
		{ "efi_bios/empty",               test_efi_bios_empty_returns_false },
		{ "efi_bios/x86_family",          test_efi_bios_x86_family_supported },
		{ "efi_bios/aarch64_family",      test_efi_bios_aarch64_family_supported },
		{ "efi_bios/non_supported",       test_efi_bios_non_supported_return_false },
	};

	return ela_run_test_suite("isa_util", cases, sizeof(cases) / sizeof(cases[0]));
}
