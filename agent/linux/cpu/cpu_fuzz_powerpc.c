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
	uint32_t v, opc;

	if (len < 4)
		return 0;
	v = cpu_fixed_get_u32(insn, isa->big_endian);
	opc = (v >> 26) & 0x3F;

	return opc == 1 || opc == 2 || opc == 4 || opc == 5 || opc == 6;
}

struct cpu_isa *cpu_isa_powerpc(const char *name)
{
	static struct cpu_isa isa;
	int le = name && strstr(name, "le");
	int is64 = name && strstr(name, "64");

	cpu_fixed_fill(&isa,
		       is64 ? (le ? "powerpc64le" : "powerpc64") : "powerpc",
		       !le, TRAP_PPC, ppc_is_reserved, NULL);
	return &isa;
}
