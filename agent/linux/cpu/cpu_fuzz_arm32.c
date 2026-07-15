// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * ARM 32-bit CPU fuzz module, covering both instruction sets:
 *   - A32 (ARM state): fixed 4-byte instructions.
 *   - T32 (Thumb-2): 2-byte, or 4-byte when the first halfword selects a
 *     32-bit Thumb-2 encoding. Selected by a name containing "thumb"; the
 *     harness enters Thumb state via the descriptor's `thumb` flag.
 *
 * The finding signal is the coprocessor space (cp0-cp7 are vendor/custom -- cp10/
 * cp11 are FP/NEON and cp14/cp15 are debug/system, all standard) and the
 * permanently-UNDEFINED encodings, which is where SoC vendors add custom
 * instructions on ARM.
 */
#include "cpu_fuzz_fixed.h"

#include <string.h>

#define BKPT_A32   0xE1200070u	/* BKPT #0 (ARM state)   */
#define BKPT_T16   0xBE00u	/* BKPT #0 (Thumb, 16-bit) */

/* ---- A32 (ARM state) ---------------------------------------------------- */

static int a32_is_reserved(struct cpu_isa *isa, const uint8_t *insn, int len)
{
	uint32_t v, op, cp;
	int is_cop;

	if (len < 4)
		return 0;
	v = cpu_fixed_get_u32(insn, isa->big_endian);

	/* Permanently UNDEFINED space: cccc 0111 1111 .... .... .... 1111 .... */
	if ((v & 0x0FF000F0u) == 0x07F000F0u)
		return 1;

	/* Coprocessor instructions: CDP/MCR/MRC (bits[27:24]==1110) and LDC/STC
	 * (bits[27:24]==110x). Coproc number is bits[11:8]; cp0-cp7 is the
	 * vendor/custom space. */
	op = (v >> 24) & 0xF;
	cp = (v >> 8) & 0xF;
	is_cop = (op == 0xE) || (op == 0xC) || (op == 0xD);
	if (is_cop && cp <= 7)
		return 1;
	return 0;
}

/* ---- T32 (Thumb) -------------------------------------------------------- */

static int thumb_next(struct cpu_isa *isa, const struct cpu_search *s,
		      uint64_t index, int feedback_len, uint8_t *out, int cap)
{
	uint32_t enc, top5;
	uint16_t hw1;
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

	hw1 = (uint16_t)enc;
	top5 = (hw1 >> 11) & 0x1F;
	/* First halfword 0b11101/0b11110/0b11111 selects a 32-bit Thumb-2. */
	if (top5 == 0x1D || top5 == 0x1E || top5 == 0x1F) {
		if (cap < 4)
			return 0;
		cpu_fixed_put_u16(out, hw1, 0);
		cpu_fixed_put_u16(out + 2, (uint16_t)(enc >> 16), 0);
		return 4;
	}
	if (cap < 2)
		return 0;
	cpu_fixed_put_u16(out, hw1, 0);
	return 2;
}

static int thumb_is_reserved(struct cpu_isa *isa, const uint8_t *insn, int len)
{
	uint16_t hw1;

	(void)isa;
	if (len < 2)
		return 0;
	hw1 = cpu_fixed_get_u16(insn, 0);

	if (len == 2) {
		/* 16-bit permanently UNDEFINED: 1101 1110 xxxx xxxx (0xDExx). */
		return (hw1 & 0xFF00) == 0xDE00;
	}
	/* 32-bit Thumb-2 coprocessor: hw1 = 1110 11xx (>>9 == 0x76/0x77);
	 * coproc number is hw2 bits[11:8]; cp0-cp7 is vendor/custom. */
	{
		uint16_t hw2 = cpu_fixed_get_u16(insn + 2, 0);
		uint32_t hi = (hw1 >> 9) & 0x7F;
		uint32_t cp = (hw2 >> 8) & 0xF;

		if ((hi == 0x76 || hi == 0x77) && cp <= 7)
			return 1;
	}
	return 0;
}

struct cpu_isa *cpu_isa_arm32(const char *name)
{
	static struct cpu_isa isa;
	int be = name && strstr(name, "be") != NULL;

	if (name && strstr(name, "thumb")) {
		memset(&isa, 0, sizeof(isa));
		isa.name = "arm32-thumb";
		isa.variable_length = 0;
		isa.min_len = 2;
		isa.max_len = 4;
		isa.align = 2;
		isa.big_endian = 0;	/* Thumb halfwords are little-endian */
		isa.thumb = 1;
		isa.next = thumb_next;
		isa.is_reserved = thumb_is_reserved;
		cpu_fixed_put_u16(isa.epilogue, BKPT_T16, 0);
		isa.epilogue_len = 2;
		return &isa;
	}

	cpu_fixed_fill(&isa, be ? "arm32-be" : "arm32", be, BKPT_A32,
		       a32_is_reserved, NULL);
	return &isa;
}
