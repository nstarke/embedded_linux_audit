// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Offline unit tests for the CPU instruction fuzzer's pure logic: candidate
 * generation (all modes, all ISAs), the reserved/vendor recognizers, byte
 * helpers, rng determinism, outcome names, and the finding-file header parser.
 * The machine-code executor, fork supervisor, streaming, and daemonization are
 * hardware/OS paths and are LCOV-excluded rather than tested here.
 */
#include "../../../agent/linux/cpu/cpu_fuzz.h"
#include "../../../agent/linux/cpu/cpu_fuzz_fixed.h"
#include "test_harness.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void test_rng_deterministic(void)
{
	uint64_t a, b;

	cpu_rng_seed(0xC0FFEE);
	a = cpu_rng_next();
	cpu_rng_seed(0xC0FFEE);
	b = cpu_rng_next();
	ELA_ASSERT_TRUE(a == b);
	/* seed 0 is remapped to a nonzero constant, still deterministic */
	cpu_rng_seed(0);
	a = cpu_rng_next();
	cpu_rng_seed(0);
	b = cpu_rng_next();
	ELA_ASSERT_TRUE(a == b);
	ELA_ASSERT_TRUE(cpu_rng_below(0) == 0);
	ELA_ASSERT_TRUE(cpu_rng_below(10) < 10);
}

static void test_outcome_names(void)
{
	ELA_ASSERT_STR_EQ("executed", cpu_outcome_name(CPU_OUT_EXECUTED));
	ELA_ASSERT_STR_EQ("sigill", cpu_outcome_name(CPU_OUT_SIGILL));
	ELA_ASSERT_STR_EQ("sigsegv", cpu_outcome_name(CPU_OUT_SIGSEGV));
	ELA_ASSERT_STR_EQ("sigbus", cpu_outcome_name(CPU_OUT_SIGBUS));
	ELA_ASSERT_STR_EQ("sigfpe", cpu_outcome_name(CPU_OUT_SIGFPE));
	ELA_ASSERT_STR_EQ("fetch-overrun", cpu_outcome_name(CPU_OUT_FETCH));
	ELA_ASSERT_STR_EQ("hang", cpu_outcome_name(CPU_OUT_HANG));
	ELA_ASSERT_STR_EQ("syscall", cpu_outcome_name(CPU_OUT_SYSCALL));
	ELA_ASSERT_STR_EQ("other", cpu_outcome_name(CPU_OUT_OTHER));
	ELA_ASSERT_STR_EQ("unknown", cpu_outcome_name(CPU_OUT_UNKNOWN));
}

static void test_byte_helpers(void)
{
	uint8_t b[4];

	cpu_fixed_put_u32(b, 0xDEADBEEF, 1);	/* big-endian */
	ELA_ASSERT_INT_EQ(0xDE, b[0]);
	ELA_ASSERT_INT_EQ(0xEF, b[3]);
	ELA_ASSERT_INT_EQ(0xDEADBEEF, cpu_fixed_get_u32(b, 1));
	cpu_fixed_put_u32(b, 0xDEADBEEF, 0);	/* little-endian */
	ELA_ASSERT_INT_EQ(0xEF, b[0]);
	ELA_ASSERT_INT_EQ(0xDE, b[3]);
	ELA_ASSERT_INT_EQ(0xDEADBEEF, cpu_fixed_get_u32(b, 0));
	cpu_fixed_put_u16(b, 0xBE00, 0);
	ELA_ASSERT_INT_EQ(0x00, b[0]);
	ELA_ASSERT_INT_EQ(0xBE, b[1]);
	ELA_ASSERT_INT_EQ(0xBE00, cpu_fixed_get_u16(b, 0));
	cpu_fixed_put_u16(b, 0xBE00, 1);
	ELA_ASSERT_INT_EQ(0xBE00, cpu_fixed_get_u16(b, 1));
}

static void test_decode_policy_rules(void)
{
	static const struct cpu_decode_rule rules[] = {
		{ 0xFC000000u, 0x48000000u, CPU_RES_VENDOR },
		{ 0xFC000000u, 0x4C000000u, CPU_RES_FEATURE_GATED },
	};

	ELA_ASSERT_INT_EQ(CPU_RES_VENDOR,
		cpu_decode_rules_u32(0x48001234u, rules, 2));
	ELA_ASSERT_INT_EQ(CPU_RES_FEATURE_GATED,
		cpu_decode_rules_u32(0x4C000000u, rules, 2));
	ELA_ASSERT_INT_EQ(CPU_RES_DEFINED,
		cpu_decode_rules_u32(0x00000000u, rules, 2));
}

/* Exercise a module's next() across all search modes and verify the byte
 * length it returns is one it declares. */
static void exercise_next(struct cpu_isa *isa)
{
	static const enum cpu_mode modes[] = {
		CPU_MODE_SWEEP, CPU_MODE_BRUTE, CPU_MODE_RANDOM, CPU_MODE_TUNNEL,
		CPU_MODE_TARGETED,
	};
	size_t m;

	for (m = 0; m < sizeof(modes) / sizeof(modes[0]); m++) {
		struct cpu_search s;
		uint8_t buf[CPU_INSN_MAX];
		int feedback = 0, i;

		memset(&s, 0, sizeof(s));
		s.mode = modes[m];
		s.max_len = isa->max_len;
		s.seed = 0x1000;
		for (i = 0; i < 4; i++) {
			int len = isa->next(isa, &s, (uint64_t)i, feedback, buf,
					    sizeof(buf));
			ELA_ASSERT_TRUE(len >= isa->min_len && len <= isa->max_len);
			feedback = len;
		}
	}
}

static void test_x86_module(void)
{
	/* Each ISA factory returns a single shared static descriptor (one fuzz
	 * run per process), so a test must finish with one before fetching
	 * another from the same factory. */
	struct cpu_isa *isa = cpu_isa_x86("x86_64");
	uint8_t salc[1] = { 0xD6 }, icebp[1] = { 0xF1 }, nop[1] = { 0x90 };

	ELA_ASSERT_TRUE(isa != NULL);
	ELA_ASSERT_TRUE(isa->variable_length == 1);
	ELA_ASSERT_TRUE(isa->prologue_len > 0);
	ELA_ASSERT_STR_EQ("x86_64", isa->name);
	/* curated undocumented/removed opcodes flagged; a NOP is not */
	ELA_ASSERT_TRUE(isa->is_reserved(isa, salc, 1));
	/* INT1/ICEBP is architecturally recognized; do not label it hidden. */
	ELA_ASSERT_FALSE(isa->is_reserved(isa, icebp, 1));
	ELA_ASSERT_FALSE(isa->is_reserved(isa, nop, 1));
	exercise_next(isa);

	/* the 32-bit variant is named by the factory */
	ELA_ASSERT_STR_EQ("x86", cpu_isa_x86("i386")->name);
}

static void test_aarch64_module(void)
{
	struct cpu_isa *isa = cpu_isa_fixed("aarch64-le");
	uint8_t udf[4] = { 0, 0, 0, 0 };		/* op0==0 reserved   */
	uint8_t nop[4] = { 0x1F, 0x20, 0x03, 0xD5 };	/* NOP, not reserved */

	ELA_ASSERT_TRUE(isa != NULL);
	ELA_ASSERT_INT_EQ(4, isa->min_len);
	ELA_ASSERT_INT_EQ(4, isa->epilogue_len);
	ELA_ASSERT_TRUE(isa->prologue_len > 0);
	ELA_ASSERT_TRUE(isa->is_reserved(isa, udf, 4));
	ELA_ASSERT_FALSE(isa->is_reserved(isa, nop, 4));
	exercise_next(isa);
	/* big-endian variant selected by name */
	ELA_ASSERT_STR_EQ("aarch64-be", cpu_isa_fixed("aarch64-be")->name);
}

static void test_arm32_and_thumb_modules(void)
{
	uint8_t mcr_cp0[4], movr0[4], udf16[2];
	struct cpu_isa *isa;

	/* A32: cp0-7 coprocessor is vendor space, a plain MOV is not. A32 and
	 * Thumb share the cpu_isa_arm32 static, so finish A32 before Thumb. */
	isa = cpu_isa_fixed("arm32");
	cpu_fixed_put_u32(mcr_cp0, 0xEE000010u, isa->big_endian);
	cpu_fixed_put_u32(movr0, 0xE1A00000u, isa->big_endian);
	ELA_ASSERT_TRUE(isa->is_reserved(isa, mcr_cp0, 4));
	ELA_ASSERT_FALSE(isa->is_reserved(isa, movr0, 4));
	exercise_next(isa);

	/* Thumb: 2-byte epilogue, thumb flag, 16-bit UDF flagged */
	isa = cpu_isa_fixed("arm32-thumb");
	ELA_ASSERT_TRUE(isa->thumb == 1);
	ELA_ASSERT_INT_EQ(2, isa->epilogue_len);
	cpu_fixed_put_u16(udf16, 0xDE00u, 0);
	ELA_ASSERT_TRUE(isa->is_reserved(isa, udf16, 2));
	exercise_next(isa);
}

static void test_mips_ppc_riscv_modules(void)
{
	struct cpu_isa *mips = cpu_isa_fixed("mips");
	struct cpu_isa *ppc = cpu_isa_fixed("powerpc");
	struct cpu_isa *rv = cpu_isa_fixed("riscv64");
	uint8_t enc[4], c[CPU_INSN_MAX];

	/* MIPS: COP2 (opcode 0x12) is vendor space */
	cpu_fixed_put_u32(enc, 0x48000000u, mips->big_endian);
	ELA_ASSERT_TRUE(mips->is_reserved(mips, enc, 4));
	ELA_ASSERT_TRUE(mips->prologue_len > 0);

	/* PowerPC is big-endian; opcode 4 is vendor SIMD */
	ELA_ASSERT_TRUE(ppc->big_endian == 1);
	cpu_fixed_put_u32(enc, 0x10000000u, ppc->big_endian);
	ELA_ASSERT_TRUE(ppc->is_reserved(ppc, enc, 4));

	/* RISC-V: 32-bit custom opcode + 16-bit compressed generation */
	ELA_ASSERT_INT_EQ(2, rv->min_len);	/* compressed instructions */
	c[0] = 0x0B; c[1] = 0; c[2] = 0; c[3] = 0;	/* custom-0 major opcode */
	ELA_ASSERT_TRUE(rv->is_reserved(rv, c, 4));
	{
		struct cpu_search s = { .mode = CPU_MODE_SWEEP, .seed = 0x0000001fu };
		int n = rv->next(rv, &s, 0, 0, c, sizeof(c));
		ELA_ASSERT_INT_EQ(6, n); /* 48-bit RISC-V parcel prefix */
	}

	exercise_next(mips);
	exercise_next(ppc);
	exercise_next(rv);

	/* the ppc64le variant re-uses the powerpc factory's shared static, so
	 * check it last -- after ppc is no longer needed. */
	ELA_ASSERT_STR_EQ("powerpc64le", cpu_isa_fixed("powerpc64le")->name);
}

static void test_isa_dispatch(void)
{
	ELA_ASSERT_TRUE(cpu_isa_for("x86_64") != NULL);
	ELA_ASSERT_TRUE(cpu_isa_for("x86") != NULL);
	ELA_ASSERT_TRUE(cpu_isa_for("aarch64") != NULL);
	ELA_ASSERT_TRUE(cpu_isa_for("arm32") != NULL);
	ELA_ASSERT_TRUE(cpu_isa_for("mips64") != NULL);
	ELA_ASSERT_TRUE(cpu_isa_for("powerpc") != NULL);
	ELA_ASSERT_TRUE(cpu_isa_for("riscv32") != NULL);
	/* unsupported / empty -> NULL */
	ELA_ASSERT_TRUE(cpu_isa_for("sparc64") == NULL);
	ELA_ASSERT_TRUE(cpu_isa_for("") == NULL);
	ELA_ASSERT_TRUE(cpu_isa_for(NULL) == NULL);
}

static void test_peek_and_show(void)
{
	char path[] = "/tmp/ela-cpu-peek-XXXXXX";
	char isa[32];
	int fd = mkstemp(path);
	const char *body =
		"# target=cpu-riscv64 mode=sweep\n"
		"0b000000 executed exec_len=4 note=custom\n"
		"73001000 sigill exec_len=4\n";

	ELA_ASSERT_TRUE(fd >= 0);
	ELA_ASSERT_TRUE(write(fd, body, strlen(body)) == (ssize_t)strlen(body));
	close(fd);

	/* peek the "# target=cpu-<isa>" header */
	ELA_ASSERT_TRUE(cpu_fuzz_peek_isa(path, isa, sizeof(isa)) == 0);
	ELA_ASSERT_STR_EQ("riscv64", isa);

	/* decode the finding file offline (no execution) */
	ELA_ASSERT_INT_EQ(0, cpu_fuzz_show(cpu_isa_for(isa), path));
	unlink(path);

	/* a file with no header returns -1; show on a missing file returns nonzero */
	ELA_ASSERT_TRUE(cpu_fuzz_peek_isa("/nonexistent/ela", isa, sizeof(isa)) != 0);
	ELA_ASSERT_TRUE(cpu_fuzz_show(cpu_isa_for("riscv64"), "/nonexistent/ela") != 0);
}

static void test_selftest_passes(void)
{
	/* The engine's own offline self-test exercises every ISA module end to
	 * end; a nonzero return would fail the suite. */
	ELA_ASSERT_INT_EQ(0, cpu_fuzz_selftest_run());
}

int run_cpu_fuzz_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "rng/deterministic", test_rng_deterministic },
		{ "outcome/names", test_outcome_names },
		{ "byte/helpers", test_byte_helpers },
		{ "decode/policy", test_decode_policy_rules },
		{ "module/x86", test_x86_module },
		{ "module/aarch64", test_aarch64_module },
		{ "module/arm32+thumb", test_arm32_and_thumb_modules },
		{ "module/mips+ppc+riscv", test_mips_ppc_riscv_modules },
		{ "isa/dispatch", test_isa_dispatch },
		{ "peek+show", test_peek_and_show },
		{ "engine/selftest", test_selftest_passes },
	};

	return ela_run_test_suite("cpu_fuzz", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
