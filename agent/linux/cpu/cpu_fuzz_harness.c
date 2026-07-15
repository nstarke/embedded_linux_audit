// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * CPU instruction fuzzer execution sandbox. Executes one fuzzer-generated
 * candidate instruction on the host CPU and classifies the result, recovering
 * from every faulting candidate via sigsetjmp/siglongjmp. A candidate that
 * corrupts machine state past what recovery can repair is NOT handled here --
 * the engine runs this inside a short-lived forked child and respawns it, so
 * such a candidate only kills the child (and is recorded as the killer).
 *
 * Two placement strategies (chosen by isa->variable_length):
 *
 *  - x86 (variable length): prepend a prologue that sets EFLAGS.TF, then place
 *    the candidate so its last byte abuts a PROT_NONE guard page. Exactly one
 *    instruction single-steps: a clean decode raises SIGTRAP whose PC gives the
 *    true length; a decode that overruns the candidate faults into the guard
 *    (SIGSEGV with si_addr in the guard) -- the sandsifter length trick.
 *
 *  - fixed-width ISAs: place the candidate followed by a trap epilogue (BRK /
 *    EBREAK / int3). A defined encoding executes and falls into the trap
 *    (SIGTRAP = executed); an undefined encoding raises SIGILL. No ucontext
 *    register access is needed -- the signal number alone classifies.
 */
#include "cpu_fuzz.h"

#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#endif

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

#define CPU_ALTSTACK_SZ 65536

struct cpu_harness {
	struct cpu_isa *isa;
	uint8_t *arena;		/* two pages: [exec][guard]                   */
	size_t   page;
	uint8_t *guard;		/* arena + page (PROT_NONE)                   */
};

/* ---- signal-handler <-> executor channel --------------------------------
 * The child that runs candidates is single-threaded, so file-scope state is a
 * safe and simple channel between the handler and the executor. */
static sigjmp_buf            g_jb;
static volatile sig_atomic_t g_active;
static volatile int          g_signo;
static volatile uintptr_t    g_si_addr;
static volatile uintptr_t    g_fault_pc;
static uintptr_t             g_guard_lo, g_guard_hi;
static struct cpu_isa       *g_isa;

/* LCOV_EXCL_START -- runs machine code; only exercised on real hardware */

/*
 * Make freshly-written code in [start,end) executable on a CPU with a
 * non-coherent instruction cache. `__builtin___clear_cache` handles this on most
 * targets, but on PowerPC it lowers to a call to libgcc's __clear_cache, which
 * is not present in this project's static link -- so we issue the dcbst/icbi/sync
 * sequence directly there. On x86 the icache is coherent and this is a no-op.
 */
static void cpu_flush_icache(void *start, void *end)
{
#if defined(__powerpc__) || defined(__powerpc64__) || defined(__ppc__) || \
	defined(__PPC__) || defined(__PPC64__)
	char *p;
	const long line = 32;	/* <= the real line size, so no line is skipped */

	for (p = (char *)start; p < (char *)end; p += line)
		__asm__ volatile("dcbst 0,%0" :: "r"(p) : "memory");
	__asm__ volatile("sync" ::: "memory");
	for (p = (char *)start; p < (char *)end; p += line)
		__asm__ volatile("icbi 0,%0" :: "r"(p) : "memory");
	__asm__ volatile("isync" ::: "memory");
#else
	__builtin___clear_cache((char *)start, (char *)end);
#endif
}

static void on_signal(int sig, siginfo_t *si, void *uc)
{
	if (!g_active) {
		/* A late SIGALRM from a candidate's watchdog that already
		 * finished is harmless -- ignore it. */
		if (sig == SIGALRM)
			return;
		/* Any other signal outside a candidate is a genuine crash:
		 * restore the default and re-raise so it is not swallowed. */
		struct sigaction dfl;

		memset(&dfl, 0, sizeof(dfl));
		dfl.sa_handler = SIG_DFL;
		sigaction(sig, &dfl, NULL);
		raise(sig);
		return;
	}
	g_signo    = sig;
	g_si_addr  = (uintptr_t)(si ? si->si_addr : NULL);
	g_fault_pc = (g_isa && g_isa->fault_pc) ? g_isa->fault_pc(uc) : 0;
	g_active   = 0;
	siglongjmp(g_jb, 1);
}

static int install_handlers(void)
{
	static int done;
	static uint8_t altstack[CPU_ALTSTACK_SZ];
	static const int sigs[] = { SIGILL, SIGSEGV, SIGBUS, SIGFPE,
				    SIGTRAP, SIGALRM, SIGSYS };
	struct sigaction sa;
	stack_t ss;
	size_t i;

	if (done)
		return 0;

	ss.ss_sp = altstack;
	ss.ss_size = sizeof(altstack);
	ss.ss_flags = 0;
	if (sigaltstack(&ss, NULL) != 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = on_signal;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
		if (sigaction(sigs[i], &sa, NULL) != 0)
			return -1;

	done = 1;
	return 0;
}

static void classify(struct cpu_isa *isa, uintptr_t start, int len,
		     struct cpu_result *res)
{
	switch (g_signo) {
	case SIGTRAP:
		/* x86: TF trap after the candidate executed; fixed: the epilogue
		 * trap after the candidate executed. Either way it ran. */
		res->outcome = CPU_OUT_EXECUTED;
		if (isa->variable_length && g_fault_pc >= start)
			res->exec_len = (int)(g_fault_pc - start);
		break;
	case SIGILL:
		res->outcome = CPU_OUT_SIGILL;
		break;
	case SIGSEGV:
		if (isa->variable_length &&
		    g_si_addr >= g_guard_lo && g_si_addr < g_guard_hi) {
			res->outcome = CPU_OUT_FETCH;	/* decode overran guard */
			res->exec_len = len;
		} else {
			res->outcome = CPU_OUT_SIGSEGV;
		}
		break;
	case SIGBUS:
		res->outcome = CPU_OUT_SIGBUS;
		break;
	case SIGFPE:
		res->outcome = CPU_OUT_SIGFPE;
		break;
	case SIGALRM:
		res->outcome = CPU_OUT_HANG;
		break;
	case SIGSYS:
		/* seccomp trapped a syscall the candidate tried to issue */
		res->outcome = CPU_OUT_SYSCALL;
		break;
	default:
		res->outcome = CPU_OUT_OTHER;
		break;
	}
}

/*
 * Place a candidate in the arena and execute it once, classifying the outcome
 * into *res. `clen` bytes of `bytes` are offered to the CPU. For variable-
 * length ISAs the candidate is placed so its last offered byte abuts the guard
 * page (a decode overrun then faults into the guard); for fixed-width ISAs it
 * is placed at the arena base followed by the trap epilogue.
 */
static void run_placed(struct cpu_harness *h, struct cpu_isa *isa,
		       const uint8_t *bytes, int clen, struct cpu_result *res)
{
	void (*volatile fn)(void);
	/* volatile: live across sigsetjmp/siglongjmp (cstart is read after the
	 * longjmp in classify), so keep them in memory, not clobberable registers. */
	uint8_t *volatile entry;
	uint8_t *volatile cstart;
	int total;

	if (isa->variable_length) {
		total = isa->prologue_len + clen;
		if (total > (int)h->page) {
			res->outcome = CPU_OUT_UNKNOWN;
			return;
		}
		entry  = h->guard - total;	/* candidate ends at guard edge */
		cstart = entry + isa->prologue_len;
		if (isa->prologue_len)
			memcpy(entry, isa->prologue, (size_t)isa->prologue_len);
		memcpy(cstart, bytes, (size_t)clen);
	} else {
		entry  = h->arena;
		cstart = h->arena;
		memcpy(entry, bytes, (size_t)clen);
		if (isa->epilogue_len)
			memcpy(entry + clen, isa->epilogue,
			       (size_t)isa->epilogue_len);
	}
	cpu_flush_icache(entry, h->guard);

	g_isa      = isa;
	g_guard_lo = (uintptr_t)h->guard;
	g_guard_hi = (uintptr_t)h->guard + h->page;
	g_signo    = 0;
	g_si_addr  = 0;
	g_fault_pc = 0;

	if (sigsetjmp(g_jb, 1) == 0) {
		/* Per-execution watchdog: a candidate that hangs (a blocking or
		 * signal-masking sequence) trips SIGALRM -> CPU_OUT_HANG. Armed
		 * around each single execution so measure_len's sub-runs are each
		 * covered; a stray late SIGALRM is ignored by the handler. */
		static const struct itimerval arm  = { {0, 0}, {0, 300000} };
		static const struct itimerval off  = { {0, 0}, {0, 0} };

		g_active = 1;
		setitimer(ITIMER_REAL, &arm, NULL);
		/* ARM Thumb: entering through a pointer with bit0 set switches the
		 * CPU to Thumb state for the candidate (a no-op flag off ARM). */
		{
			uintptr_t ep = (uintptr_t)entry;

			if (isa->thumb)
				ep |= 1;
			fn = (void (*)(void))ep;
		}
		fn();
		/* Fixed-width epilogue traps, x86 single-steps into a trap, so we
		 * normally leave via siglongjmp. Reaching here means a clean fall-
		 * through (e.g. an empty epilogue): count it as executed. */
		setitimer(ITIMER_REAL, &off, NULL);
		g_active = 0;
		res->outcome = CPU_OUT_EXECUTED;
		return;
	}

	{
		static const struct itimerval off = { {0, 0}, {0, 0} };

		setitimer(ITIMER_REAL, &off, NULL);
	}
	res->signo = g_signo;
	classify(isa, (uintptr_t)cstart, clen, res);
}

/*
 * Measure the true decoded length of a variable-length candidate by the
 * sandsifter page-boundary method: offer k = 1..len bytes with the rest in the
 * guard page; the smallest k that does NOT overrun the guard is the length.
 * This works regardless of whether the instruction executes, is #UD, or data-
 * faults -- length is a decode property. Returns 1..len, or len+1 if the decode
 * still wants more than `len` bytes (an over-long / prefix-overflow anomaly).
 */
static int measure_len(struct cpu_harness *h, struct cpu_isa *isa,
		       const uint8_t *bytes, int len)
{
	int k;

	for (k = 1; k <= len; k++) {
		struct cpu_result r;

		memset(&r, 0, sizeof(r));
		run_placed(h, isa, bytes, k, &r);
		if (r.outcome != CPU_OUT_FETCH)
			return k;	/* decoded with k bytes */
	}
	return len + 1;			/* wants more than we can offer */
}

int cpu_harness_exec(struct cpu_harness *h, const uint8_t *bytes, int len,
		     struct cpu_result *res)
{
	struct cpu_isa *isa = h->isa;

	memset(res, 0, sizeof(*res));
	if (len < 1 || len > CPU_INSN_MAX) {
		res->outcome = CPU_OUT_UNKNOWN;
		return 0;
	}
	memcpy(res->bytes, bytes, (size_t)len);
	res->len = len;
	res->exec_len = len;

	run_placed(h, isa, bytes, len, res);

	/* For variable-length ISAs, recover the true decoded length so the tunnel
	 * can steer and findings report it. A cleanly single-stepped instruction
	 * already carries its exact length (trap PC); anything else needs the
	 * page-boundary probe. */
	if (isa->variable_length && res->outcome != CPU_OUT_EXECUTED &&
	    res->outcome != CPU_OUT_HANG)
		res->exec_len = measure_len(h, isa, bytes, len);

	return 0;
}

/* LCOV_EXCL_STOP */

struct cpu_harness *cpu_harness_new(struct cpu_isa *isa)
{
	struct cpu_harness *h;
	long pg;

	if (install_handlers() != 0)
		return NULL;

	pg = sysconf(_SC_PAGESIZE);
	if (pg <= 0)
		pg = 4096;

	h = calloc(1, sizeof(*h));
	if (!h)
		return NULL;
	h->isa = isa;
	h->page = (size_t)pg;
	h->arena = mmap(NULL, h->page * 2, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (h->arena == MAP_FAILED) {
		free(h);
		return NULL;
	}
	h->guard = h->arena + h->page;
	if (mprotect(h->guard, h->page, PROT_NONE) != 0) {
		munmap(h->arena, h->page * 2);
		free(h);
		return NULL;
	}
	return h;
}

void cpu_harness_free(struct cpu_harness *h)
{
	if (!h)
		return;
	if (h->arena && h->arena != MAP_FAILED)
		munmap(h->arena, h->page * 2);
	free(h);
}

int cpu_harness_seccomp_lockdown(void)
{
#ifdef __linux__
	/*
	 * Allow only the syscalls the executor's own loop makes; everything else
	 * -- i.e. any syscall a candidate instruction issues -- is RET_TRAP'd to
	 * SIGSYS at syscall entry, before the kernel does any (possibly
	 * uninterruptible) work. Register-zeroing already reduces a candidate
	 * `syscall` to nr 0 (read/restart_syscall, deliberately NOT allowed), so
	 * this is defence-in-depth that also blocks any file/network side effects.
	 */
	static const int allowed[] = {
#ifdef __NR_rt_sigprocmask
		__NR_rt_sigprocmask,	/* sigsetjmp/siglongjmp mask save/restore */
#endif
#ifdef __NR_rt_sigreturn
		__NR_rt_sigreturn,	/* return from our signal handlers        */
#endif
#ifdef __NR_setitimer
		__NR_setitimer,		/* per-candidate hang watchdog            */
#endif
#ifdef __NR_munmap
		__NR_munmap,
#endif
#ifdef __NR_futex
		__NR_futex,		/* glibc internals (defensive)            */
#endif
#ifdef __NR_cacheflush
		__NR_cacheflush,	/* __builtin___clear_cache on arm/mips    */
#endif
#ifdef __NR_exit_group
		__NR_exit_group,
#endif
#ifdef __NR_exit
		__NR_exit,
#endif
	};
	struct sock_filter prog_body[8 + 2 * (int)(sizeof(allowed) /
						   sizeof(allowed[0]))];
	struct sock_fprog prog;
	int n = 0;
	size_t i;

	/* A = seccomp_data.nr */
	prog_body[n++] = (struct sock_filter)BPF_STMT(
		BPF_LD | BPF_W | BPF_ABS,
		(uint32_t)offsetof(struct seccomp_data, nr));
	for (i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
		/* if (A == allowed[i]) return ALLOW; */
		prog_body[n++] = (struct sock_filter)BPF_JUMP(
			BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)allowed[i], 0, 1);
		prog_body[n++] = (struct sock_filter)BPF_STMT(
			BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	}
	prog_body[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
						      SECCOMP_RET_TRAP);

	prog.len = (unsigned short)n;
	prog.filter = prog_body;

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		return -1;
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0)
		return -1;
	return 0;
#else
	return -1;
#endif
}
