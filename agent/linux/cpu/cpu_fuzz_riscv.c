// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * RISC-V (RV32/RV64) CPU fuzz module. RISC-V instructions are 32-bit, or 16-bit
 * when the C (compressed) extension is present, so this module sweeps BOTH: the
 * low two bits of an encoding decide its width exactly as the hardware decodes
 * it (0b11 -> 32-bit, otherwise a 16-bit compressed instruction). Little-endian.
 * Trap epilogue is EBREAK.
 *
 * Finding signal:
 *   - 32-bit: the custom-0/1/2/3 major opcodes (0x0B/0x2B/0x5B/0x7B) -- the
 *     space reserved by the ISA for vendor/custom instructions.
 *   - 16-bit: RVC encodings the spec marks Reserved (a natural home for vendor
 *     compressed extensions).
 */
#include "cpu_fuzz_fixed.h"

#include <string.h>

#define EBREAK_RISCV 0x00100073u	/* EBREAK */

static int riscv_next(struct cpu_isa *isa, const struct cpu_search *s,
		      uint64_t index, int feedback_len, uint8_t *out, int cap)
{
	uint32_t enc;
	uint64_t stride = s->stride ? s->stride : 1;

	(void)isa;
	(void)feedback_len;

	switch (s->mode) {
	case CPU_MODE_RANDOM:
		enc = (uint32_t)cpu_rng_next();
		break;
	case CPU_MODE_BRUTE:
		enc = (uint32_t)index;
		break;
	case CPU_MODE_SWEEP:
	default:
		enc = (uint32_t)(s->seed + index * stride);
		break;
	}

	if ((enc & 0x3) != 0x3) {		/* 16-bit compressed */
		if (cap < 2)
			return 0;
		cpu_fixed_put_u16(out, (uint16_t)enc, 0);
		return 2;
	}
	if (cap < 4)
		return 0;
	cpu_fixed_put_u32(out, enc, 0);
	return 4;
}

static int riscv_is_reserved(struct cpu_isa *isa, const uint8_t *insn, int len)
{
	(void)isa;

	if (len == 2) {
		uint16_t c = cpu_fixed_get_u16(insn, 0);
		uint32_t q = c & 0x3;		/* quadrant           */
		uint32_t f3 = (c >> 13) & 0x7;	/* funct3             */

		if (c == 0)
			return 0;		/* all-zero: defined illegal (#UD) */
		/* Quadrant 0, funct3 == 0b100 is Reserved in RVC. */
		if (q == 0 && f3 == 0x4)
			return 1;
		/* c.addi4spn (q0/f3=0) with nzuimm == 0 is Reserved. */
		if (q == 0 && f3 == 0x0 && ((c >> 5) & 0xFF) == 0)
			return 1;
		return 0;
	}
	if (len >= 4) {
		uint32_t opc = cpu_fixed_get_u32(insn, 0) & 0x7F;

		return opc == 0x0B || opc == 0x2B || opc == 0x5B || opc == 0x7B;
	}
	return 0;
}

struct cpu_isa *cpu_isa_riscv(const char *name)
{
	static struct cpu_isa isa;
	int is64 = name && strstr(name, "64");

	cpu_fixed_fill(&isa, is64 ? "riscv64" : "riscv32", 0, EBREAK_RISCV,
		       riscv_is_reserved, riscv_next);
	isa.min_len = 2;	/* compressed instructions are 2 bytes */
	isa.align = 2;
	return &isa;
}
