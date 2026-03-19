// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/isa_util.h"
#include "../../../agent/embedded_linux_audit_cmd.h"

static void test_normalize_isa_name_maps_common_aliases(void)
{
	ELA_ASSERT_STR_EQ(ELA_ISA_X86, normalize_isa_name("i686"));
	ELA_ASSERT_STR_EQ(ELA_ISA_X86_64, normalize_isa_name("amd64"));
	ELA_ASSERT_STR_EQ(ELA_ISA_AARCH64_LE, normalize_isa_name("arm64"));
	ELA_ASSERT_STR_EQ(ELA_ISA_AARCH64_BE, normalize_isa_name("aarch64_be"));
}

static void test_normalize_isa_name_preserves_unknown_values(void)
{
	ELA_ASSERT_STR_EQ("powerpc", normalize_isa_name("powerpc"));
	ELA_ASSERT_TRUE(normalize_isa_name(NULL) == NULL);
}

static void test_powerpc_family_detection_handles_aliases(void)
{
	ELA_ASSERT_TRUE(isa_is_powerpc_family("powerpc"));
	ELA_ASSERT_TRUE(isa_is_powerpc_family("ppc"));
	ELA_ASSERT_TRUE(isa_is_powerpc_family("powerpc64"));
	ELA_ASSERT_TRUE(isa_is_powerpc_family("ppc64le"));
	ELA_ASSERT_FALSE(isa_is_powerpc_family("x86_64"));
	ELA_ASSERT_FALSE(isa_is_powerpc_family(NULL));
}

static void test_efi_bios_support_matches_supported_isas(void)
{
	ELA_ASSERT_TRUE(ela_isa_supported_for_efi_bios("x86"));
	ELA_ASSERT_TRUE(ela_isa_supported_for_efi_bios("amd64"));
	ELA_ASSERT_TRUE(ela_isa_supported_for_efi_bios("aarch64-be"));
	ELA_ASSERT_FALSE(ela_isa_supported_for_efi_bios("powerpc"));
}

int run_isa_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "normalize_isa_name_maps_common_aliases", test_normalize_isa_name_maps_common_aliases },
		{ "normalize_isa_name_preserves_unknown_values", test_normalize_isa_name_preserves_unknown_values },
		{ "powerpc_family_detection_handles_aliases", test_powerpc_family_detection_handles_aliases },
		{ "efi_bios_support_matches_supported_isas", test_efi_bios_support_matches_supported_isas },
	};

	return ela_run_test_suite("isa_util", cases, sizeof(cases) / sizeof(cases[0]));
}
