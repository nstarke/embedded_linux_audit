// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * CPU instruction fuzzer engine: the search loop, the forked-child supervisor
 * that makes executing attacker-controlled code survivable, and the finding
 * file / --show / --replay / self-test machinery.
 *
 * Supervisor model: the candidate loop runs in a short-lived child so that a
 * candidate which corrupts state past sigsetjmp recovery only kills the child.
 * The parent watches a heartbeat in shared memory; on abnormal child death (a
 * signal or a watchdog timeout) it records the in-flight candidate as the
 * "killer" finding and respawns a child that resumes at the next index. With no
 * unrecoverable candidate, one child runs the whole range -- fork cost is
 * amortized to nothing.
 */
#define _GNU_SOURCE
#include "cpu_fuzz.h"
#include "cpu_fuzz_fixed.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#ifdef __linux__
#include <sys/auxv.h>
#endif
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sched.h>
#endif

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

#define CPU_WATCHDOG_SEC 3	/* backstop: kill a child stalled this long  */

/* ---- rng (xorshift64; reproducible across libcs) ------------------------ */

static uint64_t g_rng_state = 0x2545F4914F6CDD1DULL;

void cpu_rng_seed(uint64_t s)
{
	g_rng_state = s ? s : 0x2545F4914F6CDD1DULL;
}

uint64_t cpu_rng_next(void)
{
	uint64_t x = g_rng_state;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	g_rng_state = x;
	return x;
}

uint32_t cpu_rng_below(uint32_t n)
{
	if (n == 0)
		return 0;
	return (uint32_t)(cpu_rng_next() % n);
}

/* ---- small helpers ------------------------------------------------------ */

const char *cpu_outcome_name(enum cpu_outcome o)
{
	switch (o) {
	case CPU_OUT_EXECUTED: return "executed";
	case CPU_OUT_SIGILL:   return "sigill";
	case CPU_OUT_SIGSEGV:  return "sigsegv";
	case CPU_OUT_SIGBUS:   return "sigbus";
	case CPU_OUT_SIGFPE:   return "sigfpe";
	case CPU_OUT_FETCH:    return "fetch-overrun";
	case CPU_OUT_HANG:     return "hang";
	case CPU_OUT_SYSCALL:  return "syscall";
	case CPU_OUT_OTHER:    return "other";
	default:               return "unknown";
	}
}

static enum cpu_outcome outcome_from_name(const char *s)
{
	int i;

	for (i = 0; i <= CPU_OUT_OTHER; i++)
		if (!strcmp(s, cpu_outcome_name((enum cpu_outcome)i)))
			return (enum cpu_outcome)i;
	return CPU_OUT_UNKNOWN;
}

/* LCOV_EXCL_START -- only used by the live finding-file / run paths below */
static const char *mode_name(enum cpu_mode m)
{
	switch (m) {
	case CPU_MODE_TUNNEL: return "tunnel";
	case CPU_MODE_BRUTE:  return "brute";
	case CPU_MODE_RANDOM: return "random";
	case CPU_MODE_SWEEP:  return "sweep";
	case CPU_MODE_TARGETED: return "targeted";
	default:              return "?";
	}
}
/* LCOV_EXCL_STOP */

static int hex_bytes(const uint8_t *b, int len, char *out, size_t outsz)
{
	static const char hx[] = "0123456789abcdef";
	int i;
	size_t o = 0;

	for (i = 0; i < len && o + 2 < outsz; i++) {
		out[o++] = hx[b[i] >> 4];
		out[o++] = hx[b[i] & 0xF];
	}
	out[o] = '\0';
	return (int)o;
}

static void cpu_feature_snapshot(char *out, size_t outsz)
{
	struct utsname u;
	FILE *f;
	char line[512];
	const char *arch = "unknown";

#if defined(__x86_64__)
	arch = "x86_64";
#elif defined(__i386__)
	arch = "x86";
#elif defined(__aarch64__)
	arch = "aarch64";
#elif defined(__arm__)
	arch = "arm32";
#elif defined(__mips__)
	arch = "mips";
#elif defined(__powerpc64__)
	arch = "powerpc64";
#elif defined(__powerpc__)
	arch = "powerpc";
#elif defined(__riscv)
	arch = "riscv";
#endif
	if (uname(&u) != 0)
		memset(&u, 0, sizeof(u));
	snprintf(out, outsz, "arch=%s kernel=%s machine=%s online_cpus=%ld", arch,
		 u.release, u.machine, sysconf(_SC_NPROCESSORS_ONLN));
#ifdef __linux__
	snprintf(out + strlen(out), outsz - strlen(out), " hwcap=%#llx",
		(unsigned long long)getauxval(AT_HWCAP));
#ifdef AT_HWCAP2
	snprintf(out + strlen(out), outsz - strlen(out), " hwcap2=%#llx",
		(unsigned long long)getauxval(AT_HWCAP2));
#endif
#endif
	f = fopen("/proc/cpuinfo", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "Features", 8) || !strncmp(line, "flags", 5) ||
		    !strncmp(line, "model name", 10) || !strncmp(line, "isa", 3)) {
			char *p = strchr(line, ':');
			if (p) {
				for (p++; *p == ' ' || *p == '\t'; p++)
					;
				p[strcspn(p, "\r\n")] = '\0';
				snprintf(out + strlen(out), outsz - strlen(out),
					 " %.*s", 320, p);
			}
			break;
		}
	}
	fclose(f);
}

/* Parse the leading whitespace-delimited hex token of a finding line (the rest
 * of the line is the human-readable outcome/note). Stops at the first space. */
static int parse_hex(const char *s, uint8_t *out, int cap)
{
	int n = 0, hi = -1;

	while (*s == ' ' || *s == '\t')
		s++;
	for (; *s && n < cap; s++) {
		int v;

		if (*s >= '0' && *s <= '9')
			v = *s - '0';
		else if (*s >= 'a' && *s <= 'f')
			v = *s - 'a' + 10;
		else if (*s >= 'A' && *s <= 'F')
			v = *s - 'A' + 10;
		else
			break;		/* end of the hex token */
		if (hi < 0) {
			hi = v;
		} else {
			out[n++] = (uint8_t)((hi << 4) | v);
			hi = -1;
		}
	}
	return n;
}

/* LCOV_EXCL_START -- finding-file I/O, ring, and the fork/exec supervisor:
 * reached only during a live fuzz run (hardware), not by the offline tests. */

/* Is this executed candidate worth saving as a finding? */
static int is_finding(struct cpu_isa *isa, const struct cpu_result *r)
{
	if (r->confirmations < 3)
		return 0;
	if (!isa->is_reserved)
		return 0;
	/* A feature-gated or privileged instruction is expected to vary with the
	 * execution environment; retain it in statistics, not as a hidden opcode. */
	if (r->reservation == CPU_RES_FEATURE_GATED ||
	    r->reservation == CPU_RES_PRIVILEGED)
		return 0;
	if (isa->variable_length) {
		/* x86: a policy-reserved opcode decoded by the CPU, or an instruction
		 * length beyond the architectural 15-byte ceiling. A data/floating
		 * fault still proves decode, so it is evidence just like single-step. */
		if (r->exec_len > 15)
			return r->outcome == CPU_OUT_FETCH || r->outcome == CPU_OUT_EXECUTED;
		return (r->outcome == CPU_OUT_EXECUTED || r->outcome == CPU_OUT_SIGSEGV ||
			r->outcome == CPU_OUT_SIGBUS || r->outcome == CPU_OUT_SIGFPE) &&
		       isa->is_reserved(isa, r->bytes, r->exec_len);
	}
	/* fixed-width: a reserved/custom encoding the CPU did not reject. */
	switch (r->outcome) {
	case CPU_OUT_EXECUTED:
	case CPU_OUT_SIGSEGV:
	case CPU_OUT_SIGBUS:
	case CPU_OUT_SIGFPE:
		return isa->is_reserved(isa, r->bytes, r->len);
	default:
		return 0;
	}
}

static int is_candidate(struct cpu_isa *isa, const struct cpu_result *r)
{
	int confirms = r->confirmations;
	struct cpu_result tmp = *r;
	tmp.confirmations = 3;
	return confirms >= 1 && is_finding(isa, &tmp);
}

/* ---- finding file ------------------------------------------------------- */

static void finding_target_tag(struct cpu_isa *isa, char *out, size_t outsz)
{
	snprintf(out, outsz, "cpu-%s", isa->name);
}

static int finding_open_header(struct cpu_isa *isa, const struct cpu_fuzz_opts *o,
			       const char *out_dir, char *path, size_t pathsz)
{
	char tag[48];
	int fd;
	char hdr[128];
	int n;
	static unsigned seq;

	mkdir(out_dir, 0755);
	finding_target_tag(isa, tag, sizeof(tag));
	snprintf(path, pathsz, "%s/%s-%u.txt", out_dir, tag, seq++);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	n = snprintf(hdr, sizeof(hdr), "# target=%s mode=%s policy=%s cpu=%d\n", tag,
		     mode_name(o->mode), CPU_FUZZ_POLICY_VERSION, o->cpu);
	if (n < 0 || (size_t)n >= sizeof(hdr) ||
	    write(fd, hdr, (size_t)n) != n) {
		close(fd);
		return -1;
	}
	{
		char features[512];
		cpu_feature_snapshot(features, sizeof(features));
		n = snprintf(hdr, sizeof(hdr), "# host_features=%s\n", features);
		if (n < 0 || (size_t)n >= sizeof(hdr) ||
		    write(fd, hdr, (size_t)n) != n) {
			close(fd);
			return -1;
		}
	}
	return fd;
}

static void finding_write(int fd, const struct cpu_result *r)
{
	char hex[2 * CPU_INSN_MAX + 1];
	char line[256];
	int n;

	if (fd < 0)
		return;
	hex_bytes(r->bytes, r->len, hex, sizeof(hex));
	n = snprintf(line, sizeof(line),
		     "%s %s exec_len=%d signo=%d si_code=%d pc=0x%llx "
		     "sentinel=%d confirms=%d class=%d cpu=%d state=0x%llx%s%s\n",
		     hex, cpu_outcome_name(r->outcome), r->exec_len,
		     r->signo, r->si_code, (unsigned long long)r->fault_pc,
		     r->reached_sentinel, r->confirmations, r->reservation, r->cpu,
		     (unsigned long long)r->state_hash,
		     r->note[0] ? " note=" : "", r->note[0] ? r->note : "");
	if (n > 0)
		(void)!write(fd, line, (size_t)n);
}

/* ---- shared supervisor state -------------------------------------------- */

/*
 * A finding, produced by the child into the shared ring and consumed by the
 * parent (which owns the finding file and the network). The child never touches
 * a file descriptor or socket, so it can be locked down with seccomp.
 */
struct cpu_shared_finding {
	uint8_t  bytes[CPU_INSN_MAX];
	int      len;
	int      exec_len;
	int      outcome;
	int      signo;
	int      si_code;
	uintptr_t fault_pc;
	uintptr_t fault_addr;
	int      reached_sentinel;
	int      reservation;
	int      confirmations;
	uint64_t state_hash;
	int      cpu;
	char     note[96];
};

#define CPU_RING_SZ 512

struct cpu_shared {
	volatile uint64_t cur;		/* candidate index in flight          */
	volatile uint64_t start;	/* index a (re)spawned child resumes  */
	volatile uint64_t done;		/* child completed its range          */
	volatile uint64_t heartbeat;	/* bumped each iteration               */
	volatile uint64_t findings;
	volatile uint64_t counts[CPU_OUT_OTHER + 1];
	volatile int      last_feedback;
	volatile int      cur_len;
	volatile uint8_t  cur_bytes[CPU_INSN_MAX];
	/* single-producer (child) / single-consumer (parent) findings ring */
	volatile uint64_t ring_head;	/* child publishes up to here         */
	volatile uint64_t ring_tail;	/* parent has consumed up to here     */
	struct cpu_shared_finding ring[CPU_RING_SZ];
};

/* ---- the candidate loop (runs in the child) ----------------------------- */
/* Child (single producer): publish one finding into the shared ring. Pure
 * shared-memory writes -- no syscalls -- so it is safe under seccomp. Drops the
 * finding if the parent is behind and the ring is full (findings are rare). */
static void ring_push(struct cpu_shared *sh, const struct cpu_result *r)
{
	uint64_t head = sh->ring_head;
	struct cpu_shared_finding *e;

	if (head - sh->ring_tail >= CPU_RING_SZ)
		return;
	e = (struct cpu_shared_finding *)&sh->ring[head % CPU_RING_SZ];
	memcpy(e->bytes, r->bytes, sizeof(e->bytes));
	e->len = r->len;
	e->exec_len = r->exec_len;
	e->outcome = r->outcome;
	e->signo = r->signo;
	e->si_code = r->si_code;
	e->fault_pc = r->fault_pc;
	e->fault_addr = r->fault_addr;
	e->reached_sentinel = r->reached_sentinel;
	e->reservation = r->reservation;
	e->confirmations = r->confirmations;
	e->state_hash = r->state_hash;
	e->cpu = r->cpu;
	memcpy(e->note, r->note, sizeof(e->note));
	sh->ring_head = head + 1;	/* publish */
}

static void child_run(struct cpu_isa *isa, const struct cpu_fuzz_opts *o,
		      struct cpu_shared *sh)
{
	struct cpu_harness *h;
	struct cpu_search s;
	uint8_t buf[CPU_INSN_MAX];
	uint64_t i;
	int feedback;

#ifdef __linux__
	/* Never outlive the supervisor: if the parent dies (crash, kill, or a
	 * host panic taking it out), the kernel SIGKILLs this child so it can't
	 * be orphaned and keep executing candidates. */
	prctl(PR_SET_PDEATHSIG, SIGKILL);
#endif
	if (o->cpu >= 0) {
#ifdef __linux__
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(o->cpu, &set);
		(void)sched_setaffinity(0, sizeof(set), &set);
#endif
	}
	h = cpu_harness_new(isa);
	if (!h)
		_exit(3);

	memset(&s, 0, sizeof(s));
	s.mode = o->mode;
	s.max_len = o->max_len ? o->max_len : isa->max_len;
	s.seed = o->seed;
	s.stride = 1;

	cpu_rng_seed(o->seed ^ (sh->start * 0x100000001B3ULL));
	feedback = sh->last_feedback;

	/* Lock the child down: from here on, any syscall a candidate issues is
	 * trapped (SIGSYS) instead of executed. Best-effort -- if unavailable we
	 * still have register-zeroing + the watchdogs. Do this AFTER cpu_harness_new
	 * (which needs mmap/sigaction) and BEFORE executing any candidate. The
	 * child no longer touches the finding file or socket (the parent drains the
	 * shared ring), so its syscall set is tiny. */
	cpu_harness_seccomp_lockdown();

	for (i = sh->start; i < (uint64_t)o->iterations; i++) {
		struct cpu_result r;
		int len = isa->next(isa, &s, i, feedback, buf, sizeof(buf));

		if (len <= 0)
			break;		/* encoding space exhausted */

		sh->cur = i;
		sh->cur_len = len;
		memcpy((void *)sh->cur_bytes, buf, (size_t)len);

		cpu_harness_exec(h, buf, len, &r);
		r.reservation = isa->classify ?
			isa->classify(isa, r.bytes,
				      isa->variable_length ? r.exec_len : r.len) :
			((isa->is_reserved && isa->is_reserved(isa, r.bytes,
							       isa->variable_length ? r.exec_len : r.len)) ?
			 CPU_RES_RESERVED : CPU_RES_DEFINED);
		/* The parent performs the two confirmations in fresh, pinned child
		 * processes. This executor only produces the initial observation. */
		r.confirmations = 1;
#ifdef __linux__
		r.cpu = sched_getcpu();
#else
		r.cpu = -1;
#endif
		feedback = r.exec_len;
		sh->last_feedback = feedback;
		if (r.outcome <= CPU_OUT_OTHER)
			sh->counts[r.outcome]++;
		sh->heartbeat++;

		if (is_candidate(isa, &r))
			ring_push(sh, &r);
	}

	sh->done = 1;
	/* No cpu_harness_free(): _exit reclaims, and skipping munmap keeps the
	 * seccomp-allowed syscall set minimal. */
	_exit(0);
}

static int same_observation(const struct cpu_result *a, const struct cpu_result *b)
{
	return a->outcome == b->outcome && a->exec_len == b->exec_len &&
		a->reached_sentinel == b->reached_sentinel && a->si_code == b->si_code &&
		a->signo == b->signo;
}

/* Execute one confirmation in a new process. Shared memory avoids permitting
 * write(2) under the candidate's seccomp policy. */
static int confirm_fresh(struct cpu_isa *isa, const struct cpu_fuzz_opts *o,
			 const struct cpu_result *want, struct cpu_result *got)
{
	struct cpu_result *shared;
	pid_t pid;
	int status;

	shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED)
		return -1;
	memset(shared, 0, sizeof(*shared));
	pid = fork();
	if (pid == 0) {
		struct cpu_harness *h;
#ifdef __linux__
		if (want->cpu >= 0) { cpu_set_t set; CPU_ZERO(&set); CPU_SET(want->cpu, &set);
			(void)sched_setaffinity(0, sizeof(set), &set); }
#endif
		h = cpu_harness_new(isa);
		if (!h) _exit(3);
		(void)cpu_harness_seccomp_lockdown();
		cpu_harness_exec(h, want->bytes, want->len, shared);
#ifdef __linux__
		shared->cpu = sched_getcpu();
#else
		shared->cpu = -1;
#endif
		_exit(0);
	}
	if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0) {
		munmap(shared, sizeof(*shared));
		return -1;
	}
	*got = *shared;
	munmap(shared, sizeof(*shared));
	(void)o;
	return 0;
}

/* Record the candidate that killed a child as a finding. */
static void record_killer(struct cpu_isa *isa, struct cpu_shared *sh, int fd,
			  int sig, const struct cpu_fuzz_opts *o)
{
	struct cpu_result r;

	(void)isa;
	memset(&r, 0, sizeof(r));
	r.len = sh->cur_len > 0 && sh->cur_len <= CPU_INSN_MAX ? sh->cur_len : 0;
	if (r.len)
		memcpy(r.bytes, (const void *)sh->cur_bytes, (size_t)r.len);
	r.exec_len = r.len;
	r.outcome = sig == 0 ? CPU_OUT_HANG : CPU_OUT_OTHER;
	r.signo = sig;
	snprintf(r.note, sizeof(r.note), "killed-child idx=%llu %s=%d",
		 (unsigned long long)sh->cur,
		 sig == 0 ? "watchdog" : "signal", sig);
	finding_write(fd, &r);
	sh->findings++;
	/* The whole finding file is uploaded once at end of run (see
	 * cpu_fuzz_run); here we only stream the killer bytes live. */
	if (o->sink && o->sink->emit)
		o->sink->emit(o->sink->ctx, r.bytes, r.len, r.note);
	fprintf(stderr, "[!] candidate idx=%llu %s -- recorded, resuming\n",
		(unsigned long long)sh->cur, r.note);
}

static volatile sig_atomic_t g_interrupted;
static void on_sigint(int s) { (void)s; g_interrupted = 1; }

/*
 * SIGKILL a child and reap it without ever blocking forever: a candidate that
 * drove the CPU into an uninterruptible (D-state) syscall cannot be reaped
 * until it leaves the kernel, and the supervisor must not hang waiting. Returns
 * 1 if reaped within the budget, 0 if the child is wedged (unreapable).
 */
static int reap_bounded(pid_t pid, int *status)
{
	int i;

	kill(pid, SIGKILL);
	for (i = 0; i < 40; i++) {	/* ~4s at 100ms */
		struct timespec ts = { 0, 100L * 1000L * 1000L };

		if (waitpid(pid, status, WNOHANG) == pid)
			return 1;
		nanosleep(&ts, NULL);
	}
	return 0;
}

/*
 * Parent (single consumer): drain findings the child published into the ring,
 * writing each to the finding file and streaming it. The child never touches
 * the file or socket, which is what lets it run under seccomp.
 */
static void drain_ring(struct cpu_isa *isa, struct cpu_shared *sh, int fd,
			       const struct cpu_fuzz_opts *o)
{
	while (sh->ring_tail < sh->ring_head) {
		struct cpu_shared_finding *e =
			(struct cpu_shared_finding *)&sh->ring[sh->ring_tail % CPU_RING_SZ];
		struct cpu_result r;

		memset(&r, 0, sizeof(r));
		memcpy(r.bytes, e->bytes, sizeof(r.bytes));
		r.len = e->len;
		r.exec_len = e->exec_len;
		r.outcome = e->outcome;
		r.signo = e->signo;
		r.si_code = e->si_code;
		r.fault_pc = e->fault_pc;
		r.fault_addr = e->fault_addr;
		r.reached_sentinel = e->reached_sentinel;
			r.reservation = e->reservation;
			r.confirmations = e->confirmations;
			r.state_hash = e->state_hash;
			r.cpu = e->cpu;
			memcpy(r.note, e->note, sizeof(r.note));
			/* An initial observation earns a finding only after two independent,
			 * fresh-process confirmations on the same logical CPU. */
			{
				struct cpu_result c;
				int pass;
				for (pass = 0; pass < 2; pass++) {
					if (confirm_fresh(isa, o, &r, &c) != 0 ||
					    c.cpu != r.cpu || !same_observation(&r, &c))
						break;
					r.confirmations++;
				}
				if (r.confirmations == 3 && is_finding(isa, &r)) {
					finding_write(fd, &r);
					sh->findings++;
					if (o->sink && o->sink->emit)
						o->sink->emit(o->sink->ctx, r.bytes, r.len, "finding");
				} else {
					snprintf(r.note, sizeof(r.note), "unstable-clean-confirmation=%d",
						 r.confirmations);
				}
			}
			sh->ring_tail = sh->ring_tail + 1;
	}
}

static int supervise(struct cpu_isa *isa, const struct cpu_fuzz_opts *o,
		     struct cpu_shared *sh, int fd)
{
	struct sigaction sa, old_sa;
	time_t last_report = 0;

	/* Clear any interrupt latched by a PRIOR run: the interactive REPL runs
	 * each command in-process, so this static persists across invocations.
	 * Without the reset, a single Ctrl-C (or a wedged-core abort) would leave
	 * g_interrupted set and make every later run a no-op (0 candidates). */
	g_interrupted = 0;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_sigint;
	/* Save the caller's SIGINT disposition and restore it on exit so the fuzz
	 * handler does not leak into the REPL after the run. */
	sigaction(SIGINT, &sa, &old_sa);

	while (sh->start < (uint64_t)o->iterations && !g_interrupted) {
		pid_t pid = fork();
		uint64_t hb_seen = sh->heartbeat;
		time_t hb_time = time(NULL);
		int status = 0;

		if (pid < 0) {
			fprintf(stderr, "cpu fuzz: fork failed (%s); running "
				"in-process (unprotected)\n", strerror(errno));
			child_run(isa, o, sh);		/* never returns */
			return 0;
		}
		if (pid == 0)
			child_run(isa, o, sh);		/* child: never returns */

		/* parent: watch the child */
		for (;;) {
			struct timespec ts = { 0, 100L * 1000L * 1000L };
			pid_t w = waitpid(pid, &status, WNOHANG);
			time_t now;

			drain_ring(isa, sh, fd, o);		/* persist published findings */

			if (w == pid)
				break;			/* child exited */
			nanosleep(&ts, NULL);
			now = time(NULL);

			if (sh->heartbeat != hb_seen) {
				hb_seen = sh->heartbeat;
				hb_time = now;
			} else if (now - hb_time >= CPU_WATCHDOG_SEC) {
				if (!reap_bounded(pid, &status)) {
					fprintf(stderr,
						"\ncpu fuzz: candidate idx=%llu wedged a "
						"core (unreapable, D-state) -- aborting "
						"to avoid wedging more.\n",
						(unsigned long long)sh->cur);
					record_killer(isa, sh, fd, 0, o);
					g_interrupted = 1;
					break;
				}
				record_killer(isa, sh, fd, 0, o);
				sh->start = sh->cur + 1;
				break;
			}
			if (g_interrupted) {
				reap_bounded(pid, &status);
				break;
			}
			if (now != last_report) {
				last_report = now;
				fprintf(stderr,
					"\r[*] %llu/%ld  exec=%llu ill=%llu "
					"seg=%llu findings=%llu   ",
					(unsigned long long)sh->cur,
					o->iterations,
					(unsigned long long)sh->counts[CPU_OUT_EXECUTED],
					(unsigned long long)sh->counts[CPU_OUT_SIGILL],
					(unsigned long long)sh->counts[CPU_OUT_SIGSEGV],
					(unsigned long long)sh->findings);
				/* Heartbeat dead-man's-switch: stream the latest
				 * in-flight candidate so a wedge still leaves its
				 * bytes captured remotely. */
				if (o->sink && o->sink->emit && sh->cur_len > 0)
					o->sink->emit(o->sink->ctx,
						      (const uint8_t *)sh->cur_bytes,
						      sh->cur_len, "heartbeat");
			}
		}

		drain_ring(isa, sh, fd, o);	/* findings published just before exit */

		if (g_interrupted)
			break;
		if (WIFEXITED(status)) {
			if (sh->done)
				break;			/* finished the range */
			/* child exited without finishing and without a signal:
			 * treat as a fault at cur and resume. */
			record_killer(isa, sh, fd, 0, o);
			sh->start = sh->cur + 1;
		} else if (WIFSIGNALED(status)) {
			record_killer(isa, sh, fd, WTERMSIG(status), o);
			sh->start = sh->cur + 1;
		} else {
			break;
		}
	}
	fputc('\n', stderr);
	sigaction(SIGINT, &old_sa, NULL);
	return 0;
}

/* ---- replay ------------------------------------------------------------- */

static int replay(struct cpu_isa *isa, const char *path)
{
	FILE *f = fopen(path, "r");
	struct cpu_harness *h;
	char line[512];
	int n = 0;

	if (!f) {
		fprintf(stderr, "cpu fuzz: cannot open %s: %s\n", path,
			strerror(errno));
		return 1;
	}
	h = cpu_harness_new(isa);
	if (!h) {
		fprintf(stderr, "cpu fuzz: harness init failed\n");
		fclose(f);
		return 1;
	}
	printf("# replay %s on target=cpu-%s\n", path, isa->name);
	while (fgets(line, sizeof(line), f)) {
		uint8_t bytes[CPU_INSN_MAX];
		struct cpu_result r;
		char hex[2 * CPU_INSN_MAX + 1];
		int len;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		len = parse_hex(line, bytes, (int)sizeof(bytes));
		if (len < 1)
			continue;
		cpu_harness_exec(h, bytes, len, &r);
		hex_bytes(r.bytes, r.len, hex, sizeof(hex));
		printf("  %-32s -> %-13s exec_len=%d\n", hex,
		       cpu_outcome_name(r.outcome), r.exec_len);
		n++;
	}
	cpu_harness_free(h);
	fclose(f);
	printf("# replayed %d case(s)\n", n);
	return 0;
}
/* LCOV_EXCL_STOP */

/* ---- show (offline decode) & peek header -------------------------------- */

int cpu_fuzz_peek_isa(const char *path, char *out, size_t outsz)
{
	FILE *f = fopen(path, "r");
	char line[256];

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *p = strstr(line, "target=cpu-");

		if (p) {
			char *isa = p + strlen("target=cpu-");
			size_t i = 0;

			while (isa[i] && isa[i] != ' ' && isa[i] != '\n' &&
			       i + 1 < outsz) {
				out[i] = isa[i];
				i++;
			}
			out[i] = '\0';
			fclose(f);
			return i ? 0 : -1;
		}
		if (line[0] != '#')
			break;
	}
	fclose(f);
	return -1;
}

int cpu_fuzz_show(struct cpu_isa *isa, const char *path)
{
	FILE *f = fopen(path, "r");
	char line[512];
	int n = 0;

	if (!f) {
		fprintf(stderr, "cpu fuzz: cannot open %s: %s\n", path,
			strerror(errno));
		return 1;
	}
	printf("# finding file %s decoded as target=cpu-%s\n", path, isa->name);
	while (fgets(line, sizeof(line), f)) {
		uint8_t bytes[CPU_INSN_MAX];
		char hex[2 * CPU_INSN_MAX + 1];
		char *sp;
		int len, i;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		len = parse_hex(line, bytes, (int)sizeof(bytes));
		if (len < 1)
			continue;
		hex_bytes(bytes, len, hex, sizeof(hex));
		sp = strchr(line, ' ');
		printf("  %-32s %s", hex, sp ? sp + 1 : "\n");
		printf("      bytes:");
		for (i = 0; i < len; i++)
			printf(" %02x", bytes[i]);
		printf("  reserved=%s\n",
		       (isa->is_reserved && isa->is_reserved(isa, bytes, len)) ?
		       "yes" : "no");
		n++;
	}
	fclose(f);
	printf("# %d finding(s)\n", n);
	return 0;
}

/* ---- run entry ---------------------------------------------------------- */

/* LCOV_EXCL_START -- entry to the live fuzz run / replay; hardware-only */
int cpu_fuzz_run(struct cpu_isa *isa, const struct cpu_fuzz_opts *o)
{
	struct cpu_shared *sh;
	char path[512];
	int fd, rc;

	if (o->replay_path)
		return replay(isa, o->replay_path);
	if (o->all_cpus) {
		long n = sysconf(_SC_NPROCESSORS_ONLN);
		long cpu;
		int rc_all = 0;
		if (n < 1) n = 1;
		for (cpu = 0; cpu < n; cpu++) {
			struct cpu_fuzz_opts one = *o;
			one.all_cpus = 0;
			one.cpu = (int)cpu;
			rc_all |= cpu_fuzz_run(isa, &one);
		}
		return rc_all;
	}

	if (o->iterations <= 0) {
		fprintf(stderr, "cpu fuzz: --iterations must be > 0\n");
		return 2;
	}

	sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED) {
		fprintf(stderr, "cpu fuzz: shared map failed: %s\n",
			strerror(errno));
		return 1;
	}
	memset(sh, 0, sizeof(*sh));

	fd = finding_open_header(isa, o, o->out_dir, path, sizeof(path));
	if (fd < 0) {
		fprintf(stderr, "cpu fuzz: cannot create finding file in %s\n",
			o->out_dir);
		munmap(sh, sizeof(*sh));
		return 1;
	}

	fprintf(stderr,
		"[*] cpu fuzz: target=cpu-%s mode=%s iterations=%ld out=%s\n"
		"    AUTHORIZED USE ONLY -- executes generated machine code on "
		"this CPU.\n",
		isa->name, mode_name(o->mode), o->iterations, path);

	rc = supervise(isa, o, sh, fd);

	/* Upload the complete finding file to the agent API once, if streaming. */
	if (sh->findings && o->sink && o->sink->crash) {
		char *body = NULL;
		long sz;
		FILE *rf = fopen(path, "rb");

		if (rf) {
			fseek(rf, 0, SEEK_END);
			sz = ftell(rf);
			fseek(rf, 0, SEEK_SET);
			if (sz > 0 && sz < 8 * 1024 * 1024 &&
			    (body = malloc((size_t)sz + 1))) {
				if (fread(body, 1, (size_t)sz, rf) == (size_t)sz)
					o->sink->crash(o->sink->ctx, body, (int)sz);
				free(body);
			}
			fclose(rf);
		}
	}

	fprintf(stderr,
		"[+] done: executed=%llu sigill=%llu sigsegv=%llu sigbus=%llu "
		"fetch=%llu hang=%llu  findings=%llu\n    findings -> %s\n",
		(unsigned long long)sh->counts[CPU_OUT_EXECUTED],
		(unsigned long long)sh->counts[CPU_OUT_SIGILL],
		(unsigned long long)sh->counts[CPU_OUT_SIGSEGV],
		(unsigned long long)sh->counts[CPU_OUT_SIGBUS],
		(unsigned long long)sh->counts[CPU_OUT_FETCH],
		(unsigned long long)sh->counts[CPU_OUT_HANG],
		(unsigned long long)sh->findings, path);

	close(fd);
	munmap(sh, sizeof(*sh));
	return rc;
	/* LCOV_EXCL_STOP */
}

/* ---- offline self-tests (no execution) ---------------------------------- */

static int st_fail(const char *what)
{
	fprintf(stderr, "cpu selftest FAIL: %s\n", what);
	return 1;
}

int cpu_fuzz_selftest_run(void)
{
	uint8_t buf[CPU_INSN_MAX];
	struct cpu_isa *isa;
	struct cpu_search s;
	char hex[64], back_hex[64];
	uint8_t back[CPU_INSN_MAX];
	int len;

	/* rng determinism */
	cpu_rng_seed(1234);
	{
		uint64_t a = cpu_rng_next();

		cpu_rng_seed(1234);
		if (cpu_rng_next() != a)
			return st_fail("rng not reproducible");
	}

	/* outcome name round-trip */
	if (outcome_from_name("sigill") != CPU_OUT_SIGILL ||
	    outcome_from_name("executed") != CPU_OUT_EXECUTED)
		return st_fail("outcome name round-trip");

	/* hex round-trip */
	{
		uint8_t in[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

		hex_bytes(in, 4, hex, sizeof(hex));
		if (strcmp(hex, "deadbeef"))
			return st_fail("hex encode");
		if (parse_hex(hex, back, 4) != 4 || memcmp(back, in, 4))
			return st_fail("hex decode");
	}

	/* x86 module: prologue present, tunnel steps, reserved recognizer */
	isa = cpu_isa_x86("x86_64");
	if (!isa || !isa->variable_length || isa->prologue_len == 0)
		return st_fail("x86 descriptor");
	{
		uint8_t salc[1] = { 0xD6 };
		uint8_t nop[1] = { 0x90 };

		if (!isa->is_reserved(isa, salc, 1))
			return st_fail("x86 SALC not flagged reserved");
		if (isa->is_reserved(isa, nop, 1))
			return st_fail("x86 NOP wrongly flagged");
	}
	memset(&s, 0, sizeof(s));
	s.mode = CPU_MODE_TUNNEL;
	s.max_len = 15;
	len = isa->next(isa, &s, 0, 0, buf, sizeof(buf));
	if (len != 15)
		return st_fail("x86 tunnel first length");
	/* feedback length 1 should increment byte 0 from 0x00 to 0x01 */
	len = isa->next(isa, &s, 1, 1, buf, sizeof(buf));
	if (len != 15 || buf[0] != 0x01)
		return st_fail("x86 tunnel step");

	/* fixed module: aarch64 endianness + reserved region */
	isa = cpu_isa_fixed("aarch64-le");
	if (!isa || isa->variable_length || isa->min_len != 4 ||
	    isa->epilogue_len != 4)
		return st_fail("aarch64 descriptor");
	/* BRK #0 = 0xD4200000, little-endian epilogue = 00 00 20 D4 */
	if (isa->epilogue[0] != 0x00 || isa->epilogue[3] != 0xD4)
		return st_fail("aarch64 epilogue endianness");
	{
		uint8_t udf[4] = { 0x00, 0x00, 0x00, 0x00 };	/* op0==0 group */
		uint8_t nop[4] = { 0x1F, 0x20, 0x03, 0xD5 };	/* NOP, op0!=0  */

		if (!isa->is_reserved(isa, udf, 4))
			return st_fail("aarch64 reserved region");
		if (isa->is_reserved(isa, nop, 4))
			return st_fail("aarch64 NOP wrongly reserved");
	}
	memset(&s, 0, sizeof(s));
	s.mode = CPU_MODE_SWEEP;
	s.seed = 0;
	len = isa->next(isa, &s, 5, 0, buf, sizeof(buf));
	if (len != 4)
		return st_fail("aarch64 sweep length");

	/* riscv: 32-bit custom opcode + 16-bit compressed generation/recognizer */
	isa = cpu_isa_fixed("riscv64");
	if (!isa || isa->min_len != 2)
		return st_fail("riscv descriptor (compressed)");
	{
		uint8_t custom0[4] = { 0x0B, 0, 0, 0 };	/* opcode 0x0B (LE)    */

		if (!isa->is_reserved(isa, custom0, 4))
			return st_fail("riscv custom opcode");
	}
	/* A sweep value whose low 2 bits != 0b11 is a 16-bit compressed insn. */
	memset(&s, 0, sizeof(s));
	s.mode = CPU_MODE_SWEEP;
	s.seed = 0x1000;	/* 0x1000 & 3 == 0 -> compressed */
	len = isa->next(isa, &s, 0, 0, buf, sizeof(buf));
	if (len != 2)
		return st_fail("riscv compressed length");
	s.seed = 0x1003;	/* low 2 bits == 0b11 -> 32-bit */
	len = isa->next(isa, &s, 0, 0, buf, sizeof(buf));
	if (len != 4)
		return st_fail("riscv 32-bit length");

	/* arm32 A32: coprocessor cp0-7 is vendor space; a plain data-proc is not */
	isa = cpu_isa_fixed("arm32");
	{
		/* MCR p0, ... -> coproc 0 (cp<=7): reserved. Encoding cccc 1110
		 * ... 0000 (cp=0) ... 1 (MCR). 0xEE000010 = MCR p0,0,r0,c0,c0,0. */
		uint8_t mcr_cp0[4];
		uint8_t movr0[4];	/* mov r0,r0 = 0xE1A00000: not reserved */

		cpu_fixed_put_u32(mcr_cp0, 0xEE000010u, isa->big_endian);
		cpu_fixed_put_u32(movr0, 0xE1A00000u, isa->big_endian);
		if (!isa->is_reserved(isa, mcr_cp0, 4))
			return st_fail("arm32 coprocessor reserved");
		if (isa->is_reserved(isa, movr0, 4))
			return st_fail("arm32 mov wrongly reserved");
	}

	/* arm32 Thumb variant: 2-byte epilogue, thumb flag, 16-bit UDF */
	isa = cpu_isa_fixed("arm32-thumb");
	if (!isa || !isa->thumb || isa->epilogue_len != 2)
		return st_fail("thumb descriptor");
	{
		uint8_t udf[2];		/* 0xDE00 UDF (LE halfword) */

		cpu_fixed_put_u16(udf, 0xDE00u, 0);
		if (!isa->is_reserved(isa, udf, 2))
			return st_fail("thumb UDF reserved");
	}

	/* mips: COP2 (opcode 0x12) is vendor space */
	isa = cpu_isa_fixed("mips");
	{
		uint8_t cop2[4];	/* opcode 0x12 << 26 = 0x48000000 (BE) */

		cpu_fixed_put_u32(cop2, 0x48000000u, isa->big_endian);
		if (!isa->is_reserved(isa, cop2, 4))
			return st_fail("mips COP2 reserved");
	}

	/* big-endian ppc: opcode 4 is vendor SIMD (VMX/SPE); round-trip too */
	isa = cpu_isa_fixed("powerpc");
	if (!isa->big_endian)
		return st_fail("powerpc should be big-endian");
	{
		uint8_t op4[4];		/* opcode 4 << 26 = 0x10000000 */

		cpu_fixed_put_u32(op4, 0x10000000u, isa->big_endian);
		if (!isa->is_reserved(isa, op4, 4))
			return st_fail("ppc opcode-4 reserved");
	}
	memset(&s, 0, sizeof(s));
	s.mode = CPU_MODE_BRUTE;
	len = isa->next(isa, &s, 0x04000000ULL, 0, buf, sizeof(buf));
	hex_bytes(buf, len, hex, sizeof(hex));
	parse_hex(hex, back, 4);
	hex_bytes(back, 4, back_hex, sizeof(back_hex));
	if (strcmp(hex, back_hex))
		return st_fail("ppc byte round-trip");

	/* host dispatcher maps canonical names to the per-ISA modules */
	if (!cpu_isa_for("x86_64") || !cpu_isa_for("aarch64") ||
	    !cpu_isa_for("riscv64") || !cpu_isa_for("mips") ||
	    !cpu_isa_for("powerpc") || !cpu_isa_for("arm32"))
		return st_fail("cpu_isa_for mapping");

	printf("cpu selftest: OK\n");
	return 0;
}
