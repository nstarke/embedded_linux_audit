# `embedded_linux_audit linux cpu` Command

CPU instruction fuzzing — the ELA analog of
[sandsifter](https://github.com/xoreaxeaxeax/sandsifter). `cpu list` reports the
host ISA and the fuzz mode that applies; `cpu fuzz` discovers **undocumented**,
**undefined-but-present**, and **anomalous** machine instructions on the CPU the
agent is running on. It is the tool for finding a vendor's hidden/custom
instructions on an embedded SoC.

> **Authorized use only.** This executes fuzzer-generated machine code on the
> host CPU by design. Each candidate runs in a short-lived, isolated child
> process, but a hostile or buggy instruction can still wedge a CPU core, trip a
> machine-check, or touch memory-mapped state on an SoC with custom silicon. Run
> it only on hardware you own and can power-cycle — **never inside another
> sandbox or under `ptrace`/`strace`**, which will interfere with the executed
> instructions and can create unkillable (D-state) tasks.

## Why this is per-ISA

Unlike the WLAN/eth/BT fuzzers — which send *bytes to a device* and share one
grammar engine — a CPU fuzzer *executes bytes on the CPU itself*, so almost
everything is ISA-specific:

- **x86 / x86_64** are variable length (1–15 bytes); the true decoded length is
  only knowable by asking the CPU. They use a sandsifter-style **length-guided
  tunnel**: single-step one instruction with the trap flag, measure its length
  against a guard page, and increment the search from the last decoded byte so
  the otherwise-intractable encoding space becomes searchable.
- **AArch64 / ARM32 / MIPS / MIPS64 / PowerPC / RISC-V** are fixed 4-byte, so
  their 2³² encoding space is directly **swept**. A trap-instruction epilogue
  turns "the candidate executed" into a `SIGTRAP`, so the outcome is classified
  from the signal number alone.

You can only execute the ISA you are running on, so there is **no `--target`**:
the ISA is the host's, taken from the binary's compile-time architecture.

## What counts as a finding

The disassembler-free signal per ISA is an instruction that **executes** (does
not raise `SIGILL`) while lying in that ISA's reserved / vendor / custom opcode
space — exactly where hidden instructions live:

| ISA | Finding = executes AND lies in… |
|---|---|
| x86 / x86_64 | a curated set of removed/undocumented opcodes (SALC, ICEBP, `MOV`↔test-registers, reserved `0F` opcodes) |
| AArch64 | the top-level **Reserved**/unallocated decode groups + reserved system-hint numbers |
| ARM32 (A32) | the **cp0–cp7 coprocessor** (vendor) space + permanently-**UNDEFINED** encodings |
| ARM32 (Thumb) | 16-bit **UDF** + 32-bit Thumb-2 vendor coprocessor space (`--thumb`) |
| MIPS / MIPS64 | **COP2 / COP1X / SPECIAL2** vendor space + reserved SPECIAL functions |
| PowerPC | the illegal/reserved primary opcodes **1 / 2 / 5 / 6** and the vendor SIMD opcode **4** (VMX/SPE) |
| RISC-V | 32-bit **custom-0/1/2/3** opcodes (`0x0B/0x2B/0x5B/0x7B`) + reserved **16-bit compressed** encodings |

Ordinary outcomes (a normal instruction executing, a plain `SIGILL` in reserved
space) are counted in the run summary but not saved. A human triages the saved
findings with their own disassembler — ELA ships no disassembler because it is a
self-contained static binary.

## Listing (`cpu list`)

```sh
embedded_linux_audit linux cpu list
```

```text
HOST ISA       WIDTH      MODE       FUZZER
x86_64         1-15 (var) tunnel     supported

Fuzz it with: linux cpu fuzz [--mode tunnel|brute|random]
```

## Fuzzing (`cpu fuzz`)

```sh
# x86: length-guided tunnel (default), one million candidates
embedded_linux_audit linux cpu fuzz --iterations 1000000

# fixed-width: sweep the encoding space from a seed-derived base
embedded_linux_audit linux cpu fuzz --mode sweep --seed 0x40000000
```

### How it stays survivable

Executing attacker-controlled code is dangerous; four layers contain it:

1. **Register zeroing.** Before each candidate the GPRs are cleared, so an
   instruction that dereferences a register faults cleanly instead of corrupting
   the harness, and a `syscall` becomes a harmless no-op instead of an arbitrary
   (possibly uninterruptible) call.
2. **seccomp lockdown.** The executor child runs under a `seccomp` filter: any
   syscall a candidate issues is trapped to `SIGSYS` *at syscall entry* (before
   the kernel can block), recorded as a `syscall` outcome, and skipped. The child
   itself touches no file or socket — findings and streaming are handled by the
   supervisor over shared memory — so only a tiny syscall set is allowed.
3. **Fault recovery.** Signal handlers (`SIGILL/SEGV/BUS/FPE/TRAP/SYS`) classify
   the outcome and `siglongjmp` back; a per-candidate 300 ms timer turns a hang
   into a recorded `hang` finding.
4. **Forked-child isolation.** The candidate loop runs in a short-lived child.
   An instruction that corrupts state past recovery only kills the child; the
   supervisor records the killer candidate and respawns from the next index. A
   child that wedges a core unrecoverably (D-state) is detected and the run
   aborts rather than wedging more cores.

## Options

| Option | Meaning |
|---|---|
| `--mode NAME` | `tunnel` \| `brute` \| `random` (x86) or `sweep` (fixed-width); default is ISA-appropriate |
| `--iterations N` | candidates to run (default 1,000,000) |
| `--length N` | x86 max candidate byte length, 1–15 (default 15) |
| `--probe-every N` | progress / remote-stream heartbeat cadence (default 4096) |
| `--seed N` | rng seed / sweep base (default 1) |
| `--out DIR` | finding output directory (default `crashes`) |
| `--thumb` | ARM32 host only: fuzz the Thumb (T32) instruction set instead of A32 |
| `--replay FILE` | re-execute a saved/returned finding on this CPU |
| `--show FILE` | decode a finding offline (no execution) |
| `--insecure` | skip TLS verification when streaming to `--output-http` |
| `--selftest` | offline engine self-tests (no execution) |

## Finding artifacts, replay, and remote capture

A run writes a finding file to `--out` (default `crashes/`):

```text
# target=cpu-x86_64 mode=tunnel
f1000000000000000000000000000000 executed exec_len=1
d6000000000000000000000000000000 executed exec_len=1 note=...
```

The `# target=cpu-<isa>` header makes findings self-describing:

- **`--show FILE`** decodes a finding offline (host-independent) for triage,
  printing each candidate's bytes and whether it lies in the reserved region.
- **`--replay FILE`** re-executes the findings on this CPU to confirm they
  reproduce. The ISA is read from the header; replay refuses a file whose ISA
  does not match the host (you cannot execute a foreign ISA — use `--show`
  instead). This is how you replay results **returned from the fuzzing
  process**: a finding streamed to the agent API and downloaded back, or copied
  off the target, replays directly with `--replay`.

With `--output-http` set (see the transfer/remote-copy docs), `cpu fuzz` opens a
WebSocket dead-man's-switch to the agent API and streams each candidate just
before it executes, plus uploads the whole finding file at the end. If an
instruction panics the host and kills the agent, the API keeps the last streamed
candidate as a remote artifact — which you then replay with `--replay`.

## Scope and status

x86 / x86_64 get the full sandsifter-style treatment (trap-flag single-step,
guard-page length measurement, length-guided tunnel). The fixed-width ISAs each
have their own module (`cpu_fuzz_arm64.c`, `cpu_fuzz_arm32.c`, `cpu_fuzz_mips.c`,
`cpu_fuzz_powerpc.c`, `cpu_fuzz_riscv.c`) over a shared sweep core, each with a
vendor/reserved recognizer tuned to that ISA's custom-instruction space. RISC-V
also sweeps the 16-bit compressed encodings and ARM32 the Thumb (T32) set
(`--thumb`). The execution path for non-x86 ISAs (and the Thumb-state entry) is
built to be correct but must be validated on real hardware — it cannot be
exercised on an x86 build. See [the design note](cpu-fuzz-design.md) for the
full rationale, including the seccomp lockdown.
