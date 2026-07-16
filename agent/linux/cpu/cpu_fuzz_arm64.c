// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * AArch64 (ARMv8-A, 64-bit) CPU fuzz module. Fixed 4-byte instructions; the
 * finding signal is an encoding that executes (does not SIGILL) while lying in
 * an architecturally unallocated region -- where a SoC's custom instructions
 * hide. Trap epilogue is BRK #0.
 */
#include "cpu_fuzz_fixed.h"

#include <string.h>

#define BRK_AARCH64 0xD4200000u	/* BRK #0 */

/*
 * A64 top-level decode uses op0 = bits[28:25]. The recognizer flags the groups
 * the manual marks unallocated/reserved:
 *   - op0 == 0b0000            : the top-level "Reserved" group (includes UDF
 *                                and the unallocated SME/SVE-adjacent space).
 *   - op0 == 0b0001 / 0b0011   : unallocated (no top-level group defined).
 * plus the fully-reserved System hint space beyond the allocated hints, which is
 * a common home for IMPLEMENTATION DEFINED / errata instructions.
 */
static int arm64_is_reserved(struct cpu_isa *isa, const uint8_t *insn, int len)
{
	uint32_t v, op0;

	if (len < 4)
		return 0;
	v = cpu_fixed_get_u32(insn, isa->big_endian);
	op0 = (v >> 25) & 0xF;

	if (op0 == 0x0 || op0 == 0x1 || op0 == 0x3)
		return 1;	/* top-level unallocated / Reserved group */

	/* System instructions (op0==0b0100, C4.1) with the "hint" encoding
	 * (0xD503201F is NOP): flag reserved hint numbers, a classic spot for
	 * IMPLEMENTATION DEFINED debug/errata ops. HINT = 1101 0101 0000 0011
	 * 0010 xxxx xxx1 1111. */
	if ((v & 0xFFFFF01Fu) == 0xD503201Fu) {
		uint32_t hint = (v >> 5) & 0x7F;

		if (hint > 0x27)	/* beyond the allocated hint numbers */
			return 1;
	}
	return 0;
}

static enum cpu_reservation arm64_classify(struct cpu_isa *isa,
						 const uint8_t *insn, int len)
{
	uint32_t v;
	if (len < 4)
		return CPU_RES_DEFINED;
	v = cpu_fixed_get_u32(insn, isa->big_endian);
	if ((v & 0xFFFFF01Fu) == 0xD503201Fu && ((v >> 5) & 0x7F) > 0x27)
		return CPU_RES_IMPLEMENTATION;
	return arm64_is_reserved(isa, insn, len) ? CPU_RES_RESERVED : CPU_RES_DEFINED;
}

struct cpu_isa *cpu_isa_arm64(const char *name)
{
	static struct cpu_isa isa;
	int be = name && strstr(name, "be") != NULL;

	cpu_fixed_fill(&isa, be ? "aarch64-be" : "aarch64-le", be,
		       BRK_AARCH64, arm64_is_reserved, NULL);
	isa.classify = arm64_classify;
	return &isa;
}
