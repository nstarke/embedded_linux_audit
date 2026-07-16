// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * PowerPC / PowerPC64 CPU fuzz module. Fixed 4-byte instructions; the finding
 * signal is an encoding that executes while lying in PowerPC's illegal/reserved
 * or vendor primary-opcode space. Trap epilogue is `tw 31,0,0` (an unconditional
 * trap). Default endianness is big; ppc64le selects little-endian.
 *
 * Primary opcode is bits[0:5] (the top 6 bits, big-endian bit numbering). The
 * recognizer flags:
 *   1, 5, 6 : architecturally illegal/reserved primary opcodes
 *   4       : the vendor SIMD space -- AltiVec/VMX on server parts, SPE on
 *             Freescale e500 -- so "opcode 4 executed" also detects vendor SIMD
 *   2       : tdi (64-bit trap immediate) -- reserved on 32-bit parts
 */
#include "cpu_fuzz_fixed.h"

#include <string.h>

#define TRAP_PPC 0x7FE00008u	/* tw 31,0,0 */

static int ppc_is_reserved(struct cpu_isa *isa, const uint8_t *insn, int len)
{
	static const struct cpu_decode_rule policy[] = {
		{ 0xFC000000u, 0x04000000u, CPU_RES_RESERVED },
		{ 0xFC000000u, 0x10000000u, CPU_RES_VENDOR },
		{ 0xFC000000u, 0x14000000u, CPU_RES_RESERVED },
		{ 0xFC000000u, 0x18000000u, CPU_RES_RESERVED },
	};
	uint32_t v;

	if (len < 4)
		return 0;
	v = cpu_fixed_get_u32(insn, isa->big_endian);
	return cpu_decode_rules_u32(v, policy, sizeof(policy) / sizeof(policy[0]))
		!= CPU_RES_DEFINED;
}

static enum cpu_reservation ppc_classify(struct cpu_isa *isa,
					 const uint8_t *insn, int len)
{
	uint32_t v;
	if (len < 4)
		return CPU_RES_DEFINED;
	v = cpu_fixed_get_u32(insn, isa->big_endian);
	{
		static const struct cpu_decode_rule policy[] = {
			{ 0xFC000000u, 0x04000000u, CPU_RES_RESERVED },
			{ 0xFC000000u, 0x10000000u, CPU_RES_VENDOR },
			{ 0xFC000000u, 0x14000000u, CPU_RES_RESERVED },
			{ 0xFC000000u, 0x18000000u, CPU_RES_RESERVED },
		};
		return cpu_decode_rules_u32(v, policy, sizeof(policy) / sizeof(policy[0]));
	}
}

struct cpu_isa *cpu_isa_powerpc(const char *name)
{
	static struct cpu_isa isa;
	int le = name && strstr(name, "le");
	int is64 = name && strstr(name, "64");

	cpu_fixed_fill(&isa,
		       is64 ? (le ? "powerpc64le" : "powerpc64") : "powerpc",
		       !le, TRAP_PPC, ppc_is_reserved, NULL);
	isa.classify = ppc_classify;
	return &isa;
}
