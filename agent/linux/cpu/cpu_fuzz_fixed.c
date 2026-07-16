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
#include <ucontext.h>

/*
 * Index of NIP (the PC) within a PowerPC general-register set, from the
 * kernel's asm/ptrace.h (r0-r31, then nip).  No libc header exposes PT_NIP, and
 * including asm/ptrace.h alongside sys/ucontext.h conflicts on PowerPC, so the
 * one constant we need is spelled out here.
 */
#define ELA_PPC_PT_NIP 32

/* Linux names the PC differently on each fixed-width target.  Keeping this
 * here means the common trampoline can verify that the sentinel, rather than
 * an instruction-generated trap, ended execution. */
uintptr_t cpu_fixed_fault_pc(void *ctx)
{
	ucontext_t *u = (ucontext_t *)ctx;

#if defined(__aarch64__)
	return (uintptr_t)u->uc_mcontext.pc;
#elif defined(__arm__)
	return (uintptr_t)u->uc_mcontext.arm_pc;
#elif defined(__mips__)
	return (uintptr_t)u->uc_mcontext.pc;
#elif defined(__powerpc64__)
	/*
	 * Read NIP out of the general-register array rather than via
	 * uc_mcontext.regs: glibc only forward-declares `struct pt_regs` in
	 * sys/ucontext.h, so dereferencing that pointer does not compile (musl
	 * defines the struct, which is why only the glibc targets failed).
	 * gp_regs is present and identically laid out on both libcs.
	 */
	return (uintptr_t)u->uc_mcontext.gp_regs[ELA_PPC_PT_NIP];
#elif defined(__powerpc__)
# if defined(__GLIBC__)
	/*
	 * 32-bit glibc does not store the context inline: uc_mcontext is a
	 * `union uc_regs_ptr` of pointers into uc_reg_space, so the register
	 * array is one dereference further out than on every other target.
	 */
	return u->uc_mcontext.uc_regs
		? (uintptr_t)u->uc_mcontext.uc_regs->gregs[ELA_PPC_PT_NIP] : 0;
# else
	return (uintptr_t)u->uc_mcontext.gregs[ELA_PPC_PT_NIP];
# endif
#elif defined(__riscv)
# ifdef REG_PC
	return (uintptr_t)u->uc_mcontext.__gregs[REG_PC];
# else
	return (uintptr_t)u->uc_mcontext.__gregs[0];
# endif
#else
	(void)u;
	return 0;
#endif
}

uint64_t cpu_fixed_state_hash(void *ctx)
{
	ucontext_t *u = (ucontext_t *)ctx;
	uint64_t h = 1469598103934665603ULL;
	const uint8_t *p = NULL;
	size_t n = 0;

/* Hash the machine context as supplied by the kernel.  This deliberately
 * includes PC/status/registers and gives every ISA the same reproducible,
 * low-cost semantic observation without assuming a particular register file. */
#if defined(__aarch64__)
	p = (const uint8_t *)&u->uc_mcontext; n = sizeof(u->uc_mcontext);
#elif defined(__arm__)
	p = (const uint8_t *)&u->uc_mcontext; n = sizeof(u->uc_mcontext);
#elif defined(__powerpc__) && !defined(__powerpc64__) && defined(__GLIBC__)
	/* 32-bit glibc's uc_mcontext is a union of POINTERS into uc_reg_space,
	 * not the context itself; hashing it directly would hash an address
	 * (near-constant across candidates) instead of the register state, so
	 * every observation would look identical.  Hash what it points at. */
	p = (const uint8_t *)u->uc_mcontext.uc_regs;
	n = u->uc_mcontext.uc_regs ? sizeof(*u->uc_mcontext.uc_regs) : 0;
#elif defined(__mips__) || defined(__powerpc__) || defined(__powerpc64__) || defined(__riscv)
	p = (const uint8_t *)&u->uc_mcontext; n = sizeof(u->uc_mcontext);
#else
	(void)u;
#endif
	while (n--) {
		h ^= *p++;
		h *= 1099511628211ULL;
	}
	return h;
}

static void fixed_zero_prologue(struct cpu_isa *isa)
{
	int r, off = 0;
	uint32_t w;

	/* Do not clobber the stack pointer; the C call/longjmp machinery relies on
	 * it.  Every other GPR is made deterministic before the candidate. */
	if (strstr(isa->name, "aarch64")) {
		for (r = 0; r <= 30; r++) {
			w = 0xAA1F03E0u | (uint32_t)r; /* mov xR, xzr */
			cpu_fixed_put_u32(isa->prologue + off, w, isa->big_endian); off += 4;
		}
	} else if (strstr(isa->name, "arm32") && !isa->thumb) {
		for (r = 0; r <= 14; r++) {
			if (r == 13) continue;
			w = 0xE3A00000u | ((uint32_t)r << 12); /* mov rR,#0 */
			cpu_fixed_put_u32(isa->prologue + off, w, isa->big_endian); off += 4;
		}
	} else if (strstr(isa->name, "mips")) {
		for (r = 1; r <= 31; r++) {
			if (r == 29) continue;
			w = 0x24000000u | ((uint32_t)r << 16); /* addiu rR,zero,0 */
			cpu_fixed_put_u32(isa->prologue + off, w, isa->big_endian); off += 4;
		}
	} else if (strstr(isa->name, "powerpc")) {
		for (r = 0; r <= 31; r++) {
			if (r == 1) continue;
			w = 0x38000000u | ((uint32_t)r << 21); /* li rR,0 */
			cpu_fixed_put_u32(isa->prologue + off, w, isa->big_endian); off += 4;
		}
	} else if (strstr(isa->name, "riscv")) {
		for (r = 1; r <= 31; r++) {
			if (r == 2) continue;
			w = 0x00000013u | ((uint32_t)r << 7); /* addi xR,x0,0 */
			cpu_fixed_put_u32(isa->prologue + off, w, 0); off += 4;
		}
	}
	isa->prologue_len = off;
}

enum cpu_reservation cpu_fixed_classify_reserved(struct cpu_isa *isa,
						 const uint8_t *insn, int len)
{
	return (isa->is_reserved && isa->is_reserved(isa, insn, len)) ?
		CPU_RES_RESERVED : CPU_RES_DEFINED;
}

enum cpu_reservation cpu_decode_rules_u32(uint32_t word,
					 const struct cpu_decode_rule *rules, size_t nr)
{
	size_t i;
	for (i = 0; i < nr; i++)
		if ((word & rules[i].mask) == rules[i].value)
			return rules[i].reservation;
	return CPU_RES_DEFINED;
}

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
	case CPU_MODE_TARGETED:
		/* Boundary corpus: vary the low fields around each ISA's
		 * reserved/custom major opcode. This reaches useful candidates far
		 * sooner than treating the 32-bit space as uniformly random. */
		if (strstr(isa->name, "aarch64")) {
			static const uint32_t a[] = { 0x00000000u, 0x02000000u,
				0x06000000u, 0x0A000000u };
			enc = a[index % (sizeof(a) / sizeof(a[0]))] |
				(uint32_t)(index / (sizeof(a) / sizeof(a[0])));
		} else if (strstr(isa->name, "mips")) {
			static const uint32_t m[] = { 0x48000000u, 0x4C000000u,
				0x70000000u, 0x78000000u };
			enc = m[index % (sizeof(m) / sizeof(m[0]))] |
				(uint32_t)(index / (sizeof(m) / sizeof(m[0])));
		} else if (strstr(isa->name, "powerpc")) {
			static const unsigned p[] = { 1, 2, 4, 5, 6 };
			enc = (uint32_t)p[index % (sizeof(p) / sizeof(p[0]))] << 26;
			enc |= (uint32_t)(index / (sizeof(p) / sizeof(p[0]))) & 0x03FFFFFFu;
		} else if (strstr(isa->name, "riscv")) {
			static const unsigned v[] = { 0x0B, 0x2B, 0x5B, 0x7B };
			enc = ((uint32_t)(index / 4) << 7) | v[index % 4];
		} else {
			/* ARM A32 coprocessor/custom and permanently-undefined forms. */
			enc = (index & 1) ? 0xE70000F0u : 0xEE000010u;
			enc |= (uint32_t)(index / 2) & 0x0000FF00u;
		}
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
	isa->classify = cpu_fixed_classify_reserved;
	isa->fault_pc = cpu_fixed_fault_pc;
	isa->state_hash = cpu_fixed_state_hash;
	cpu_fixed_put_u32(isa->epilogue, trap_word, big_endian);
	isa->epilogue_len = 4;
	fixed_zero_prologue(isa);
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
