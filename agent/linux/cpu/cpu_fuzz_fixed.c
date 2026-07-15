// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Shared core for the fixed-width CPU fuzz modules. Fixed-width ISAs all execute
 * the same way -- sweep the encoding space, place the candidate followed by a
 * trap epilogue, classify by signal number -- so the mechanics live here and
 * each per-ISA file (cpu_fuzz_arm64.c, cpu_fuzz_arm32.c, cpu_fuzz_mips.c,
 * cpu_fuzz_powerpc.c, cpu_fuzz_riscv.c) supplies only its trap encoding, byte
 * order, generator, and reserved/vendor recognizer.
 *
 * This file also holds the top-level host-ISA dispatcher (cpu_isa_for) and the
 * fixed-width name router (cpu_isa_fixed).
 */
#include "cpu_fuzz_fixed.h"
#include "util/isa_util.h"

#include <string.h>

void cpu_fixed_put_u32(uint8_t *out, uint32_t v, int big_endian)
{
	if (big_endian) {
		out[0] = (uint8_t)(v >> 24);
		out[1] = (uint8_t)(v >> 16);
		out[2] = (uint8_t)(v >> 8);
		out[3] = (uint8_t)(v);
	} else {
		out[0] = (uint8_t)(v);
		out[1] = (uint8_t)(v >> 8);
		out[2] = (uint8_t)(v >> 16);
		out[3] = (uint8_t)(v >> 24);
	}
}

uint32_t cpu_fixed_get_u32(const uint8_t *in, int big_endian)
{
	if (big_endian)
		return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
		       ((uint32_t)in[2] << 8) | (uint32_t)in[3];
	return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
	       ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

void cpu_fixed_put_u16(uint8_t *out, uint16_t v, int big_endian)
{
	if (big_endian) {
		out[0] = (uint8_t)(v >> 8);
		out[1] = (uint8_t)(v);
	} else {
		out[0] = (uint8_t)(v);
		out[1] = (uint8_t)(v >> 8);
	}
}

uint16_t cpu_fixed_get_u16(const uint8_t *in, int big_endian)
{
	if (big_endian)
		return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
	return (uint16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
}

int cpu_fixed_next4(struct cpu_isa *isa, const struct cpu_search *s,
		    uint64_t index, int feedback_len, uint8_t *out, int cap)
{
	uint32_t enc;
	uint64_t stride = s->stride ? s->stride : 1;

	(void)feedback_len;
	if (cap < 4)
		return 0;

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
	cpu_fixed_put_u32(out, enc, isa->big_endian);
	return 4;
}

void cpu_fixed_fill(struct cpu_isa *isa, const char *name, int big_endian,
		    uint32_t trap_word,
		    int (*is_reserved)(struct cpu_isa *, const uint8_t *, int),
		    int (*next)(struct cpu_isa *, const struct cpu_search *,
				uint64_t, int, uint8_t *, int))
{
	memset(isa, 0, sizeof(*isa));
	isa->name = name;
	isa->variable_length = 0;
	isa->min_len = 4;
	isa->max_len = 4;
	isa->align = 4;
	isa->big_endian = big_endian;
	isa->next = next ? next : cpu_fixed_next4;
	isa->is_reserved = is_reserved;
	isa->fault_pc = NULL;	/* classified by signal number alone */
	cpu_fixed_put_u32(isa->epilogue, trap_word, big_endian);
	isa->epilogue_len = 4;
}

/* ---- name routing ------------------------------------------------------- */

struct cpu_isa *cpu_isa_fixed(const char *name)
{
	if (!name)
		return NULL;

	if (strstr(name, "aarch64") || strstr(name, "arm64"))
		return cpu_isa_arm64(name);
	if (isa_is_arm32_family(name) || !strcmp(name, "arm32") ||
	    strstr(name, "thumb"))
		return cpu_isa_arm32(name);
	if (strstr(name, "mips"))
		return cpu_isa_mips(name);
	if (strstr(name, "ppc") || strstr(name, "powerpc"))
		return cpu_isa_powerpc(name);
	if (strstr(name, "riscv"))
		return cpu_isa_riscv(name);
	return NULL;
}

struct cpu_isa *cpu_isa_for(const char *name)
{
	const char *n;

	if (!name || !*name)
		return NULL;

	n = normalize_isa_name(name);
	if (!n)
		n = name;

	if (!strcmp(n, "x86") || !strcmp(n, "x86_64") ||
	    !strcmp(n, "i386") || !strcmp(n, "amd64"))
		return cpu_isa_x86(n);

	return cpu_isa_fixed(n);
}
