// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * x86 / x86_64 CPU fuzz module (variable-length ISA). Implements the sandsifter
 * approach: a prologue sets EFLAGS.TF so the candidate single-steps, and the
 * harness places the candidate against a guard page so a decode overrun is
 * observable. This module owns candidate generation (tunnel / brute / random)
 * and the fault-PC extraction the harness uses to measure the executed length.
 *
 * Without a bundled disassembler we can't flag every CPU-vs-decoder length
 * disagreement, so the disassembler-free "undocumented" signal here is: a
 * curated set of removed/undocumented opcodes (SALC, ICEBP, MOV to/from test
 * registers, ...) that EXECUTE instead of raising #UD -- surfaced via
 * is_reserved() -- plus decode-overrun anomalies surfaced by the engine.
 */
#define _GNU_SOURCE
#include "cpu_fuzz.h"

#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
#include <ucontext.h>
#endif

/*
 * Prologue executed immediately before each candidate. It first zeroes the
 * general-purpose registers (except the stack pointer) so a candidate that
 * dereferences a register hits address ~0 and faults cleanly (caught by the
 * harness) instead of silently corrupting the harness through a live pointer --
 * this is why sandsifter clears registers before every candidate. It then sets
 * EFLAGS.TF (pushf ; orb $1,1(%rsp) ; popf) so exactly the candidate single-
 * steps. Zeroing runs with TF still clear, so only the candidate traps.
 */
#if defined(__x86_64__)
static const uint8_t X86_TF_PROLOGUE[] = {
	0x31, 0xC0,		/* xor eax,eax  (also clears rax upper) */
	0x31, 0xDB,		/* xor ebx,ebx */
	0x31, 0xC9,		/* xor ecx,ecx */
	0x31, 0xD2,		/* xor edx,edx */
	0x31, 0xF6,		/* xor esi,esi */
	0x31, 0xFF,		/* xor edi,edi */
	0x31, 0xED,		/* xor ebp,ebp */
	0x45, 0x31, 0xC0,	/* xor r8d,r8d */
	0x45, 0x31, 0xC9,	/* xor r9d,r9d */
	0x45, 0x31, 0xD2,	/* xor r10d,r10d */
	0x45, 0x31, 0xDB,	/* xor r11d,r11d */
	0x45, 0x31, 0xE4,	/* xor r12d,r12d */
	0x45, 0x31, 0xED,	/* xor r13d,r13d */
	0x45, 0x31, 0xF6,	/* xor r14d,r14d */
	0x45, 0x31, 0xFF,	/* xor r15d,r15d */
	0x9C,			/* pushfq */
	0x80, 0x4C, 0x24, 0x01, 0x01,	/* orb $1, 1(%rsp)  (set TF) */
	0x9D,			/* popfq */
};
#else	/* i386 */
static const uint8_t X86_TF_PROLOGUE[] = {
	0x31, 0xC0,		/* xor eax,eax */
	0x31, 0xDB,		/* xor ebx,ebx */
	0x31, 0xC9,		/* xor ecx,ecx */
	0x31, 0xD2,		/* xor edx,edx */
	0x31, 0xF6,		/* xor esi,esi */
	0x31, 0xFF,		/* xor edi,edi */
	0x31, 0xED,		/* xor ebp,ebp */
	0x9C,			/* pushf */
	0x80, 0x4C, 0x24, 0x01, 0x01,	/* orb $1, 1(%esp)  (set TF) */
	0x9D,			/* popf */
};
#endif

struct x86_state {
	uint8_t ins[CPU_INSN_MAX];	/* current working instruction bytes */
	int     started;
};

/* ---- fault PC (for executed-length measurement) ------------------------- */
/* LCOV_EXCL_START -- reads a live signal ucontext; hardware-only */
static uintptr_t x86_fault_pc(void *uc)
{
#if defined(__x86_64__)
	ucontext_t *u = uc;
	return (uintptr_t)u->uc_mcontext.gregs[REG_RIP];
#elif defined(__i386__)
	ucontext_t *u = uc;
	return (uintptr_t)u->uc_mcontext.gregs[REG_EIP];
#else
	(void)uc;
	return 0;
#endif
}
/* LCOV_EXCL_STOP */

/* ---- candidate generation ----------------------------------------------- */

static int x86_next(struct cpu_isa *isa, const struct cpu_search *s,
		    uint64_t index, int feedback_len, uint8_t *out, int cap)
{
	struct x86_state *st = isa->priv;
	int n = s->max_len;
	int p, i;

	if (n < 1)
		n = 1;
	if (n > CPU_INSN_MAX)
		n = CPU_INSN_MAX;
	if (n > cap)
		n = cap;

	if (s->mode == CPU_MODE_RANDOM) {
		uint64_t r = 0;

		for (i = 0; i < n; i++) {
			if ((i & 7) == 0)
				r = cpu_rng_next() ^ (index * 0x9E3779B97F4A7C15ULL);
			out[i] = (uint8_t)(r & 0xFF);
			r >>= 8;
		}
		return n;
	}

	if (s->mode == CPU_MODE_BRUTE) {
		uint64_t v = index;

		memset(out, 0, (size_t)n);
		for (i = 0; i < n && i < 8; i++) {
			out[i] = (uint8_t)(v & 0xFF);
			v >>= 8;
		}
		return n;
	}
	if (s->mode == CPU_MODE_TARGETED) {
		static const uint8_t corpus[][3] = {
			{ 0xD6, 0x90, 0x90 }, { 0xF1, 0x90, 0x90 },
			{ 0x82, 0xC0, 0x00 }, { 0x0F, 0x04, 0x90 },
			{ 0x0F, 0x0A, 0x90 }, { 0x0F, 0x24, 0xC0 },
			{ 0x0F, 0x26, 0xC0 }, { 0x0F, 0x39, 0x90 },
		};
		memset(out, 0x90, (size_t)n);
		memcpy(out, corpus[index % (sizeof(corpus) / sizeof(corpus[0]))],
		       (size_t)(n < 3 ? n : 3));
		return n;
	}

	/* CPU_MODE_TUNNEL (default): steer by the previous candidate's length. */
	if (!st->started || index == 0) {
		memset(st->ins, 0, sizeof(st->ins));
		st->started = 1;
		memcpy(out, st->ins, (size_t)n);
		return n;
	}

	p = feedback_len > 0 ? feedback_len - 1 : n - 1;
	if (p >= n)
		p = n - 1;
	if (p < 0)
		p = 0;

	for (;;) {
		if (p < 0)
			return 0;	/* whole space explored */
		if (st->ins[p] == 0xFF) {
			st->ins[p] = 0;
			p--;
			continue;
		}
		st->ins[p]++;
		break;
	}
	if (p + 1 < n)
		memset(st->ins + p + 1, 0, (size_t)(n - (p + 1)));

	memcpy(out, st->ins, (size_t)n);
	return n;
}

/* ---- disassembler-free "undocumented" recognizer ------------------------ */

/* Skip legacy prefixes and REX, return the effective opcode and whether it was
 * a two-byte (0F) opcode. Minimal, single-byte-opcode aware. */
static int x86_primary_opcode(const uint8_t *b, int len, int *is0f, int *modrm_reg)
{
	int i = 0;

	*is0f = 0;
	*modrm_reg = -1;
	while (i < len) {
		uint8_t c = b[i];
		/* legacy prefixes */
		if (c == 0x66 || c == 0x67 || c == 0xF0 || c == 0xF2 ||
		    c == 0xF3 || c == 0x2E || c == 0x36 || c == 0x3E ||
		    c == 0x26 || c == 0x64 || c == 0x65) {
			i++;
			continue;
		}
		/* REX (x86_64) */
		if ((c & 0xF0) == 0x40) {
			i++;
			continue;
		}
		break;
	}
	if (i >= len)
		return -1;
	if (b[i] == 0x0F) {
		*is0f = 1;
		i++;
		if (i >= len)
			return -1;
	}
	{
		int op = b[i];

		if (i + 1 < len)
			*modrm_reg = (b[i + 1] >> 3) & 7;
		return op;
	}
}

static int x86_is_reserved(struct cpu_isa *isa, const uint8_t *insn, int len)
{
	int is0f, reg, op;

	(void)isa;
	op = x86_primary_opcode(insn, len, &is0f, &reg);
	if (op < 0)
		return 0;

	if (!is0f) {
		switch (op) {
		case 0xD6:	/* SALC   -- undocumented, still present on many */
		case 0xF1:	/* ICEBP/INT1 -- undocumented                    */
		case 0x82:	/* alias of 0x80 -- invalid in 64-bit mode       */
			return 1;
		default:
			return 0;
		}
	}
	/* two-byte (0F) opcodes that are removed/reserved on modern CPUs */
	switch (op) {
	case 0x04:	/* reserved                                        */
	case 0x0A:	/* reserved                                        */
	case 0x0C:	/* reserved                                        */
	case 0x24:	/* MOV r32, TRn -- removed after i486               */
	case 0x26:	/* MOV TRn, r32 -- removed after i486               */
	case 0x25:	/* reserved                                        */
	case 0x27:	/* reserved                                        */
	case 0x36:	/* reserved                                        */
	case 0x39:	/* reserved                                        */
		return 1;
	default:
		return 0;
	}
}

static enum cpu_reservation x86_classify(struct cpu_isa *isa,
					 const uint8_t *insn, int len)
{
	return x86_is_reserved(isa, insn, len) ? CPU_RES_UNKNOWN : CPU_RES_DEFINED;
}

struct cpu_isa *cpu_isa_x86(const char *name)
{
	static struct x86_state st;
	static struct cpu_isa isa;

	memset(&st, 0, sizeof(st));
	memset(&isa, 0, sizeof(isa));
	isa.name = (name && strstr(name, "64")) ? "x86_64" : "x86";
	isa.variable_length = 1;
	isa.min_len = 1;
	isa.max_len = 15;
	isa.align = 1;
	isa.big_endian = 0;
	memcpy(isa.prologue, X86_TF_PROLOGUE, sizeof(X86_TF_PROLOGUE));
	isa.prologue_len = (int)sizeof(X86_TF_PROLOGUE);
	isa.epilogue_len = 0;	/* TF single-steps; no trap epilogue needed */
	isa.next = x86_next;
	isa.is_reserved = x86_is_reserved;
	isa.classify = x86_classify;
	isa.fault_pc = x86_fault_pc;
	isa.priv = &st;
	return &isa;
}
