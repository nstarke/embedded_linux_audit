// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Shared core for the fixed-width CPU fuzz modules (AArch64, ARM32/Thumb, MIPS,
 * PowerPC, RISC-V). Each per-ISA file (cpu_fuzz_arm64.c, ...) provides only what
 * differs -- its trap/break encoding, byte order, candidate generator, and
 * reserved/vendor recognizer -- and reuses the sweep engine and byte helpers
 * declared here. This mirrors the one-file-per-target layout of the WLAN/eth
 * fuzz targets.
 */
#ifndef CPU_FUZZ_FIXED_H
#define CPU_FUZZ_FIXED_H

#include "cpu_fuzz.h"

/* Lay a 32/16-bit instruction word into memory in the ISA's instruction byte
 * order, and read it back. */
void     cpu_fixed_put_u32(uint8_t *out, uint32_t v, int big_endian);
uint32_t cpu_fixed_get_u32(const uint8_t *in, int big_endian);
void     cpu_fixed_put_u16(uint8_t *out, uint16_t v, int big_endian);
uint16_t cpu_fixed_get_u16(const uint8_t *in, int big_endian);
uintptr_t cpu_fixed_fault_pc(void *ucontext);
enum cpu_reservation cpu_fixed_classify_reserved(struct cpu_isa *,
						 const uint8_t *, int);

/* Generic 4-byte sweep/brute/random candidate generator (the default next). */
int cpu_fixed_next4(struct cpu_isa *isa, const struct cpu_search *s,
		    uint64_t index, int feedback_len, uint8_t *out, int cap);

/*
 * Fill a descriptor for a standard 4-byte fixed-width ISA. `trap_word` is laid
 * out in `big_endian` order as the 4-byte trap epilogue; `is_reserved` is the
 * ISA's finding recognizer; `next` defaults to cpu_fixed_next4 when NULL.
 */
void cpu_fixed_fill(struct cpu_isa *isa, const char *name, int big_endian,
		    uint32_t trap_word,
		    int (*is_reserved)(struct cpu_isa *, const uint8_t *, int),
		    int (*next)(struct cpu_isa *, const struct cpu_search *,
				uint64_t, int, uint8_t *, int));

#endif /* CPU_FUZZ_FIXED_H */
