# `linux cpu fuzz` — Design & Plan

CPU instruction fuzzing for ELA: discover **undocumented, undefined-but-present,
and anomalous machine instructions** on the CPU the agent is running on. This is
the ELA analog of [sandsifter](https://github.com/xoreaxeaxeax/sandsifter)
(Christopher Domas, "Breaking the x86 Instruction Set", DEF CON 25), generalized
to the ISAs ELA already targets.

> **Authorized use only.** This executes attacker-controlled (fuzzer-generated)
> machine code on the host CPU by design. It is isolated in short-lived child
> processes, but a hostile or buggy instruction can still wedge a core, trip a
> machine-check, or (on an embedded SoC with custom silicon) touch
> memory-mapped state. Run it on hardware you own and can power-cycle.

## Why this is ISA-specific

Unlike the WLAN/eth/BT fuzzers — which send *bytes to a device* over a transport
and therefore share one grammar-driven engine — a CPU fuzzer *executes bytes on
the CPU itself*. Everything below the search loop is ISA-dependent:

- **Instruction length.** x86 is variable-length (1–15 bytes) and its true
  decoded length is only knowable by asking the CPU. AArch64/ARM32/MIPS/PowerPC
  are fixed 4-byte; RISC-V and ARM Thumb are 2-or-4-byte.
- **Encoding space.** A fixed-width ISA has a tractable 2^32 encoding space you
  can *sweep* (with masking/striding); x86's up-to-2^120 space is only
  searchable with a length-guided *tunnel*.
- **"Undocumented" signal.** For a fixed-width ISA it's "an encoding the manual
  marks reserved/undefined that the CPU nonetheless *executes* (no `SIGILL`)".
  For x86 it's classically "a length or validity the CPU disagrees with a
  disassembler about" — but we don't ship a disassembler (see below), so we use
  the same execute-vs-`SIGILL` signal plus length-boundary anomalies.
- **Register/PC recovery** after a fault comes from `ucontext_t`, whose layout
  is per-ISA.

So, like the plan asked: one implementation per ISA, behind a shared driver.

## What sandsifter does (and what we borrow / drop)

Sandsifter's core mechanics, and our disposition:

| Sandsifter mechanism | ELA disposition |
|---|---|
| **Page-boundary length measurement** — place the candidate so its bytes end at the last mapped byte before an unmapped guard page; if the CPU fetches past the true instruction end it takes a `SIGSEGV` whose fault address reveals the length. | **Kept**, for x86. This is the only portable way to learn an x86 instruction's true length without a decoder. |
| **Single-step via the trap flag (TF)** — set `EFLAGS.TF` so exactly one instruction executes and the CPU raises `SIGTRAP`; the trap PC minus the start PC is the executed length. | **Kept**, for x86. Fixed-width ISAs don't need it (width is known); we use a fault/return-sled classification instead. |
| **Signal-handler + recovery** — handlers for `SIGILL/SIGSEGV/SIGBUS/SIGFPE/SIGTRAP` classify the outcome and resume the search. | **Kept and hardened.** We additionally run each batch in a *forked child*, so an instruction that corrupts state past what a handler can repair only kills the child; the parent respawns and resumes (sandsifter's Python driver respawns the C harness for the same reason — we make it a first-class in-tool mechanism). |
| **Three search strategies** — brute-force increment, random, and **tunnel** (increment guided by observed length, the key to making the space tractable). | **Kept.** `--mode tunnel` (default for x86), `--mode brute`, `--mode random`. Fixed-width ISAs use `--mode sweep` (stride the 32-bit space). |
| **Disassembler comparison (Capstone)** — flag CPU/disassembler disagreements as candidate undocumented instructions. | **Dropped.** ELA is a self-contained static binary with no runtime deps; bundling Capstone violates that. Instead we surface the raw, still-valuable signals: *executes despite lying in a reserved/undefined encoding region*, *length anomalies at page boundaries*, and *unexpected fault class*. A human triages the saved findings with their own disassembler offline. |

## Architecture

```
agent/linux/linux_cpu_cmd.c      cpu list | cpu fuzz (arg parse, dispatch, list)
agent/linux/cpu/
  cpu_fuzz.h                     shared types: cpu_isa vtable, result, options
  cpu_fuzz_harness.c             ISA-independent execution sandbox + seccomp lockdown
  cpu_fuzz_engine.c              supervisor (fork/respawn/findings-ring drain),
                                   finding-file I/O, show/peek, selftest
  cpu_fuzz_stream.c              --output-http dead-man's-switch (WebSocket)
  cpu_fuzz_x86.c                 variable-length module (x86 / x86_64)
  cpu_fuzz_fixed.[ch]            shared fixed-width core: sweep, byte helpers,
                                   descriptor fill, host-ISA dispatcher
  cpu_fuzz_arm64.c               AArch64
  cpu_fuzz_arm32.c               ARM A32 + Thumb (T32)
  cpu_fuzz_mips.c                MIPS / MIPS64
  cpu_fuzz_powerpc.c             PowerPC / PowerPC64
  cpu_fuzz_riscv.c               RISC-V (32-bit + 16-bit compressed)
```

The five fixed-width ISAs each get their own file (matching the WLAN/eth
one-file-per-target layout) but share `cpu_fuzz_fixed.c` — they are mechanically
identical (4-byte sweep, trap epilogue, signal-number classification), so a file
carries only its trap encoding, byte order, generator, and reserved/vendor
recognizer. RISC-V and ARM Thumb override the generator to emit their 16-bit
forms.

Everything below the command layer is new code; it deliberately does **not**
reuse the WLAN `struct target`/grammar engine, because that engine models a
*byte-sink transport*, not code execution. It **does** reuse the finding-file
conventions (a `# target=` header + case lines, `--show`/`--replay`, an
`--output-http` remote-capture stream) so triage tooling is uniform across all
four fuzzers.

### The execution sandbox (`cpu_fuzz_harness.c`)

The dangerous part, made safe and informative:

1. **Two-page arena.** `mmap` an RWX code page immediately followed by a
   `PROT_NONE` guard page (`MAP_FIXED` into a reserved 2-page region). A
   candidate is copied so its **last byte abuts the guard page**, so any fetch
   past the intended end faults into the guard with a known address → x86 length.
2. **A shared result page.** `mmap(MAP_SHARED|MAP_ANONYMOUS)` a small struct
   *before* forking. The child records, per candidate, its index, the resulting
   signal, and (when known) the executed length. The parent reads it after the
   child exits — so even a candidate that *kills the child outright* still has
   its index recorded (the parent classifies it from `waitpid` status and
   respawns from the next index).
3. **Batched forked execution.** The parent forks one child that processes a
   *run* of candidates in-process: for each, arm `sigsetjmp`, install the signal
   handlers (which record the outcome and `siglongjmp` back), execute, record,
   advance. Only a truly unrecoverable candidate ends the child; the parent then
   respawns from `shared->cur + 1`. This amortizes fork cost across thousands of
   candidates while keeping full isolation.
4. **Outcome classification** (per candidate):
   - `EXECUTED` — ran and control returned via the trailing return-sled /
     single-step trap. It's a *real* instruction.
   - `SIGILL` — undefined/invalid on this CPU.
   - `SIGSEGV`/`SIGBUS` — a real instruction that made a memory access (load/
     store/branch) with our arbitrary operands; *present*, not undefined.
   - `SIGFPE` — a real arithmetic instruction.
   - `SIGTRAP` — single-step completion (x86) or a breakpoint-class instruction.
   - `LENGTH` — x86 only: measured length differs from the fetched byte count in
     a way worth recording (e.g., prefixes accepted beyond the architectural
     limit, or a length boundary anomaly).

The **finding** is an outcome that is *interesting for the chosen ISA*: for a
fixed-width sweep, an encoding in a documented-reserved region that does **not**
`SIGILL`; for x86, a length/validity anomaly. Uninteresting outcomes (a plain
`SIGILL` in reserved space, a normal documented instruction executing) are
counted but not saved.

### Per-ISA module (`struct cpu_isa`)

```c
struct cpu_isa {
    const char *name;              /* canonical: "x86_64", "aarch64", ... */
    int   variable_length;         /* 1 = x86-style, 0 = fixed/sweep       */
    int   min_len, max_len;        /* instruction byte bounds              */
    int   big_endian;              /* instruction byte order in findings   */

    /* produce the candidate bytes for search position `pos` (mode-specific);
       returns byte length, or 0 to end the search. */
    int  (*emit)(struct cpu_isa *, const struct cpu_search *, uint64_t pos,
                 uint8_t *out, int cap);

    /* is this encoding in a documented reserved/undefined region worth
       flagging if it executes?  (fixed-width discovery signal) */
    int  (*is_reserved)(struct cpu_isa *, const uint8_t *insn, int len);

    /* extract the fault PC from a ucontext, for length measurement / to tell
       "candidate faulted" from "executed then trapped". */
    void *(*fault_pc)(void *ucontext);

    /* arm single-step (set TF on x86); no-op on fixed-width ISAs. */
    void (*arm_singlestep)(void *ucontext);
};
```

`cpu_fuzz_x86.c` implements the variable-length path (tunnel/brute/random +
page-boundary length measurement + `EFLAGS.TF`). `cpu_fuzz_fixed.c` implements
one generic fixed-width sweep and a small descriptor per fixed-width ISA
(width, endianness, ucontext PC index, and a table of reserved encoding
regions from the ISA manual). Adding an ISA later = one descriptor.

### Host-ISA selection

You can only execute the ISA you're running on, so `cpu fuzz` selects the module
matching the binary's **compile-time** ISA (`ARCH_ISA` from `arch_target.h`) —
the binary is native to its target. `ELA_TEST_ISA` can override the *name* for
offline `--show`/selftest, but never to execute a foreign ISA.

## Command surface

```
linux cpu list                 detect host ISA; show the fuzz mode that applies
linux cpu fuzz [options]
  --mode tunnel|brute|random|sweep   search strategy (default: ISA-appropriate)
  --iterations N                     candidates to run (default 1000000)
  --length N                         x86: max candidate byte length (default 15)
  --seed N                           rng seed (random/tunnel jitter)
  --probe-every N                    liveness/heartbeat interval
  --out DIR                          finding output dir (default crashes)
  --replay FILE                      re-execute a saved finding on this CPU
  --show FILE                        decode a finding offline (no execution)
  --insecure                         skip TLS verify when streaming (--output-http)
  --selftest                         offline engine self-tests (no execution)
```

Findings and streaming reuse the existing conventions: a `# target=cpu-<isa>`
header, one line per candidate, `--output-http` opens the same
WebSocket dead-man's-switch stream (endpoint `cpu-fuzz`) so a candidate that
hangs/panics the core still leaves its bytes captured remotely.

## Delivery plan

1. **Doc** (this file). ✔
2. **Core** — `cpu_fuzz.h` + `cpu_fuzz_harness.c` (fork-isolated executor,
   shared result page, handlers, recovery). The harness works ISA-agnostically
   from `waitpid` classification alone, so it's functional before any ucontext
   register work.
3. **Engine + ISA modules** — `cpu_fuzz_engine.c`, `cpu_fuzz_x86.c` (full:
   tunnel + length measurement), `cpu_fuzz_fixed.c` (generic sweep + aarch64
   descriptor complete; arm32/mips/powerpc/riscv descriptors wired via the same
   path). Offline `--selftest`, `--show`, `--peek`.
4. **Command + wiring** — `linux_cpu_cmd.c`, `embedded_linux_audit_cmd.h` decl,
   `embedded_linux_audit.c` dispatch + help, `Makefile` sources.
5. **Docs/tests** — user doc `cpu-fuzz.md`, README row, shell arg-test, and a
   host-`gcc` compile-check of every new translation unit.

## Hardening notes

Executing arbitrary code has failure modes beyond a clean fault; how each is
contained:

- **Register-borne corruption / rogue syscalls.** With live register values, a
  memory-writing instruction can silently corrupt the harness through a stray
  pointer, and a `syscall` can invoke an arbitrary (possibly uninterruptible)
  call. The prologue **zeroes the GPRs** before each candidate, so a dereference
  faults cleanly at ~0 and a `syscall` degrades to `read(0, NULL, 0)`. This is
  the single most important mitigation and mirrors sandsifter.
- **Hangs.** A candidate that clears the trap flag and loops, or blocks, is
  caught by a per-candidate 300 ms `SIGALRM`; the parent's 3 s stall watchdog is
  the backstop.
- **Unreapable (D-state) wedge.** If a candidate drives a core into an
  uninterruptible kernel path, even `SIGKILL` cannot reap it until it returns.
  The supervisor's kill is **bounded** (it never blocks forever) and, on
  detecting an unreapable child, it **aborts the run** rather than wedging more
  cores. `PR_SET_PDEATHSIG(SIGKILL)` ensures a child can never be orphaned.
- **`seccomp` (implemented).** The executor child runs under a `seccomp` filter
  (`cpu_harness_seccomp_lockdown`): its own loop syscalls are allow-listed and
  everything else — i.e. any syscall a candidate issues — is `RET_TRAP`'d to
  SIGSYS *at syscall entry*, before the kernel does any uninterruptible work.
  This eliminates the D-state class rather than just bounding it. It is why the
  finding-file writes and streaming were moved out of the child into the
  supervisor (over a shared-memory findings ring): the child touches no fd or
  socket, so its syscall set is tiny (setitimer, sigprocmask/sigreturn,
  exit_group, cacheflush). A trapped candidate syscall is caught in-process as a
  `syscall` outcome and the loop continues. Best-effort: if seccomp is
  unavailable the tool falls back to register-zeroing + bounded-reap.
  **Do not** run nested inside another seccomp/ptrace sandbox — the outer
  monitor intercepts the executed instructions and can itself create the D-state
  tasks this design avoids on bare metal.

## Scope of the first cut

x86/x86_64 gets the full sandsifter-style treatment (length measurement +
tunnel). AArch64 gets the full fixed-width sweep with a real reserved-region
table. ARM32/MIPS/MIPS64/PowerPC/PowerPC64/RISC-V are wired through the same
generic sweep with a starter descriptor each (width/endianness/PC recovery +
a conservative reserved table), ready to deepen. The forked-isolation
classification path is ISA-independent, so every listed ISA produces useful
findings on day one; the per-ISA reserved tables are the natural place to grow
precision.
