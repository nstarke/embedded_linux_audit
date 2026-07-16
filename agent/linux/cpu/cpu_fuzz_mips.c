// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * MIPS / MIPS64 CPU fuzz module. Fixed 4-byte instructions; the finding signal
 * is an encoding that executes while lying in MIPS's coprocessor / reserved
 * opcode space -- where SoC vendors (and MIPS ASE extensions) add non-standard
 * instructions. Trap epilogue is BREAK. Default endianness is big; the *el
 * name variants select little-endian.
 */
#include "cpu_fuzz_fixed.h"

#include <string.h>

#define BREAK_MIPS 0x0000000Du	/* BREAK */

/*
 * Primary opcode is bits[31:26]. Flag the vendor/reserved primary opcodes:
 *   0x12 COP2   : coprocessor 2 -- fully vendor-defined (custom instructions)
 *   0x13 COP1X  : reserved/removed outside MIPS64 FPU
 *   0x1C SPECIAL2: vendor/ASE space (MUL, madd, plus IMPLEMENTATION DEFINED)
 *   0x1E        : reserved (repurposed by MSA/vendor)
 * For SPECIAL (0x00) also flag the reserved MOVCI/reserved function encodings
 * that are a common IMPLEMENTATION DEFINED home.
 */
static int mips_is_reserved(struct cpu_isa *isa, const uint8_t *insn, int len)
{
	uint32_t v, opc;

	if (len < 4)
		return 0;
	v = cpu_fixed_get_u32(insn, isa->big_endian);
	opc = (v >> 26) & 0x3F;

	if (opc == 0x12 || opc == 0x13 || opc == 0x1C || opc == 0x1E)
		return 1;

	/* SPECIAL (opcode 0) with a reserved function field (0x01 MOVCI and the
	 * architecturally-reserved 0x05/0x0A.. slots historically used for
	 * vendor ops). */
	if (opc == 0x00) {
		uint32_t funct = v & 0x3F;

		if (funct == 0x01 || funct == 0x05 || funct == 0x0E)
			return 1;
	}
	return 0;
}

static enum cpu_reservation mips_classify(struct cpu_isa *isa,
						 const uint8_t *insn, int len)
{
	uint32_t v;
	if (len < 4)
		return CPU_RES_DEFINED;
	v = cpu_fixed_get_u32(insn, isa->big_endian);
	if (((v >> 26) & 0x3F) == 0x12 || ((v >> 26) & 0x3F) == 0x1C)
		return CPU_RES_VENDOR;
	return mips_is_reserved(isa, insn, len) ? CPU_RES_RESERVED : CPU_RES_DEFINED;
}

struct cpu_isa *cpu_isa_mips(const char *name)
{
	static struct cpu_isa isa;
	int le = name && (strstr(name, "el") || strstr(name, "le"));
	int is64 = name && strstr(name, "64");

	cpu_fixed_fill(&isa, is64 ? "mips64" : "mips", !le, BREAK_MIPS,
		       mips_is_reserved, NULL);
	isa.classify = mips_classify;
	return &isa;
}
