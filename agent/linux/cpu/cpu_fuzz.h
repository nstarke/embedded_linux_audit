// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * CPU instruction fuzzer core types. Discovers undocumented / undefined-but-
 * present / anomalous machine instructions on the CPU the agent is running on
 * -- the ELA analog of sandsifter, generalized across ELA's target ISAs.
 *
 * This is deliberately NOT the WLAN/eth/BT grammar engine: that engine models a
 * byte-sink transport, whereas this executes candidate bytes on the CPU itself.
 * Only the finding-file / --show / --replay / --output-http conventions are
 * shared with the other fuzzers so triage tooling is uniform.
 *
 * See docs/agent/linux/cpu-fuzz-design.md for the full rationale.
 */
#ifndef CPU_FUZZ_H
#define CPU_FUZZ_H

#include <stddef.h>
#include <stdint.h>

/* x86's architectural maximum instruction length is 15; round up for the
 * prologue/epilogue stubs the harness prepends/appends. */
#define CPU_INSN_MAX     16
#define CPU_STUB_MAX     64

enum cpu_mode {
	CPU_MODE_TUNNEL = 0,	/* length-guided increment (x86 default)        */
	CPU_MODE_BRUTE,		/* dense increment of the encoding number        */
	CPU_MODE_RANDOM,	/* random encodings                              */
	CPU_MODE_SWEEP,		/* fixed-width: stride the 32/16-bit space       */
	CPU_MODE_TARGETED,	/* reserved-field and extension boundary corpus  */
};

/* Outcome of executing one candidate. Ordering matters only for stats. */
enum cpu_outcome {
	CPU_OUT_UNKNOWN = 0,
	CPU_OUT_EXECUTED,	/* ran to completion (trap epilogue / TF trap)   */
	CPU_OUT_SIGILL,		/* undefined / invalid opcode on this CPU        */
	CPU_OUT_SIGSEGV,	/* real insn: memory access with our operands    */
	CPU_OUT_SIGBUS,		/* real insn: misaligned / bus error             */
	CPU_OUT_SIGFPE,		/* real insn: arithmetic fault                   */
	CPU_OUT_FETCH,		/* x86: decode overran into the guard page       */
	CPU_OUT_HANG,		/* watchdog fired (branch-to-self / stall)       */
	CPU_OUT_SYSCALL,	/* candidate attempted a syscall (seccomp trap)  */
	CPU_OUT_OTHER,		/* some other signal                             */
};

enum cpu_reservation {
	CPU_RES_DEFINED = 0,
	CPU_RES_RESERVED,
	CPU_RES_UNDEFINED,
	CPU_RES_IMPLEMENTATION,
	CPU_RES_VENDOR,
	CPU_RES_FEATURE_GATED,
	CPU_RES_PRIVILEGED,
	CPU_RES_UNKNOWN,
};

const char *cpu_outcome_name(enum cpu_outcome o);

/* Search parameters visible to the ISA module's emit() callback. */
struct cpu_search {
	enum cpu_mode mode;
	int      max_len;	/* x86 candidate byte cap (<= 15)                */
	uint64_t seed;
	uint64_t stride;	/* sweep stride (fixed-width)                    */
};

/* One executed candidate: also the unit written to / read from a finding file. */
struct cpu_result {
	uint8_t  bytes[CPU_INSN_MAX];
	int      len;		/* bytes offered to the CPU                      */
	int      exec_len;	/* measured executed length (x86); else == len   */
	enum cpu_outcome outcome;
	int      signo;		/* raw signal number when signal-classified      */
	int      si_code;		/* architecture/kernel-specific signal reason  */
	uintptr_t fault_pc;	/* PC reported by the signal context             */
	uintptr_t fault_addr;	/* fault address, when supplied                   */
	int      reached_sentinel;	/* fixed-width candidate reached its epilogue */
	enum cpu_reservation reservation;
	int      confirmations;
	char     note[96];
};

/* ---- per-ISA module ----------------------------------------------------- */

struct cpu_isa {
	const char *name;	/* canonical ISA name (see isa_util normalize)   */
	int   variable_length;	/* 1 = x86-style TF path; 0 = fixed-width sweep  */
	int   min_len, max_len;	/* candidate byte bounds                         */
	int   align;		/* required instruction alignment in bytes       */
	int   big_endian;	/* byte order for finding-file rendering         */
	int   thumb;		/* ARM: enter Thumb (T32) state to execute       */

	/* Machine-code stub the harness prepends before the candidate (x86: set
	 * the trap flag). May be empty. */
	uint8_t prologue[CPU_STUB_MAX];
	int     prologue_len;
	/* Machine-code stub appended after the candidate so a clean execution
	 * ends in a trap we can catch (fixed-width: a BRK/EBREAK/int3). x86 uses
	 * the trap flag instead and leaves this empty. */
	uint8_t epilogue[CPU_STUB_MAX];
	int     epilogue_len;

	/* Produce the next candidate's bytes. `index` is the monotonically
	 * increasing candidate counter; `feedback_len` is the executed length of
	 * the PREVIOUS candidate (the x86 tunnel steers by it; stateless modes
	 * ignore it). Persistent search state, if any, lives in isa->priv (one
	 * search per process). Returns the byte length, or 0 when the space is
	 * exhausted. */
	int  (*next)(struct cpu_isa *isa, const struct cpu_search *s,
		     uint64_t index, int feedback_len, uint8_t *out, int cap);

	/* Is this encoding in a documented reserved/undefined region -- i.e. one
	 * whose *execution* (no SIGILL) is a finding? Fixed-width discovery
	 * signal; x86 returns 0 (it uses length/validity anomalies instead). */
	int  (*is_reserved)(struct cpu_isa *isa, const uint8_t *insn, int len);
	/* Optional precise category used by the finding classifier. */
	enum cpu_reservation (*classify)(struct cpu_isa *isa,
					 const uint8_t *insn, int len);

	/* Extract the faulting program counter from a ucontext_t* (x86 length
	 * measurement). NULL when the ISA classifies by signal number alone. */
	uintptr_t (*fault_pc)(void *ucontext);

	void *priv;
};

/* Return the module for a canonical ISA name, or NULL if unsupported. */
struct cpu_isa *cpu_isa_for(const char *name);

/* x86 / x86_64 (variable length). */
struct cpu_isa *cpu_isa_x86(const char *name);

/* Fixed-width ISA dispatcher: routes a canonical name to the per-ISA module. */
struct cpu_isa *cpu_isa_fixed(const char *name);

/* Per-ISA fixed-width modules (each in its own file, sharing the sweep core). */
struct cpu_isa *cpu_isa_arm64(const char *name);	/* AArch64            */
struct cpu_isa *cpu_isa_arm32(const char *name);	/* ARM A32, or T32 if
							 * name has "thumb"    */
struct cpu_isa *cpu_isa_mips(const char *name);		/* MIPS / MIPS64      */
struct cpu_isa *cpu_isa_powerpc(const char *name);	/* PowerPC / PPC64    */
struct cpu_isa *cpu_isa_riscv(const char *name);	/* RISC-V (incl. C)   */

/* ---- execution harness (the sandbox) ------------------------------------ */

struct cpu_harness;

struct cpu_harness *cpu_harness_new(struct cpu_isa *isa);
void cpu_harness_free(struct cpu_harness *h);

/*
 * Execute one candidate in isolation and classify it into *res. Runs in the
 * calling process using sigsetjmp/siglongjmp recovery, so it is safe against
 * every candidate that faults; a candidate that corrupts state past recovery
 * is contained by the engine's forked-child supervisor, not here. Returns 0.
 */
int cpu_harness_exec(struct cpu_harness *h, const uint8_t *bytes, int len,
		     struct cpu_result *res);

/*
 * Lock the calling process down with a seccomp filter so a candidate that
 * issues a syscall is trapped at syscall entry (SIGSYS, before the kernel does
 * any uninterruptible work) rather than executing it -- this eliminates the
 * D-state-wedge class. Only the executor's own loop syscalls are allowed. Call
 * once, in the child, AFTER cpu_harness_new() and BEFORE the candidate loop.
 * Best-effort: returns 0 if applied, -1 if seccomp is unavailable (the caller
 * then relies on register-zeroing alone). Not undoable.
 */
int cpu_harness_seccomp_lockdown(void);

/* ---- engine (search loop, finding I/O) ---------------------------------- */

/*
 * Optional remote-capture sink (the --output-http dead-man's-switch), mirroring
 * the WLAN/eth/BT fuzzers: emit() streams each candidate JUST BEFORE it runs so
 * a candidate that wedges the core still leaves its bytes captured remotely;
 * crash() uploads a confirmed finding file. Both best-effort; NULL to disable.
 */
struct cpu_fuzz_payload_sink {
	void *ctx;
	void (*emit)(void *ctx, const uint8_t *bytes, int len, const char *note);
	void (*crash)(void *ctx, const char *findingfile, int len);
};

struct cpu_fuzz_opts {
	enum cpu_mode mode;
	int   mode_explicit;
	long  iterations;
	int   max_len;		/* x86 candidate cap; 0 = ISA default            */
	int   probe_every;	/* progress/heartbeat cadence                    */
	uint64_t seed;
	const char *out_dir;
	const char *replay_path;	/* if set: replay instead of search      */
	const struct cpu_fuzz_payload_sink *sink;
};

int cpu_fuzz_run(struct cpu_isa *isa, const struct cpu_fuzz_opts *o);

/* Offline engine self-tests (no code execution). */
int cpu_fuzz_selftest_run(void);

/* Decode a finding file into a human-readable breakdown (no execution). */
int cpu_fuzz_show(struct cpu_isa *isa, const char *path);

/* Read the "# target=cpu-<isa>" header a finding file records into out. */
int cpu_fuzz_peek_isa(const char *path, char *out, size_t outsz);

/* Reproducible xorshift rng (no libc rand -- stable across libcs via --seed). */
void     cpu_rng_seed(uint64_t s);
uint64_t cpu_rng_next(void);
uint32_t cpu_rng_below(uint32_t n);

#endif /* CPU_FUZZ_H */
