#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux cpu fuzz subcommand argument coverage"

# NOTE: never invoke a live `cpu fuzz` here -- it executes generated machine
# code on the CPU. Only non-executing paths (list/help/selftest/show) are safe
# in CI.

run_exact_case "linux cpu fuzz --help" 0 "$BIN" linux cpu fuzz --help
run_exact_case "linux cpu fuzz -h" 0 "$BIN" linux cpu fuzz -h
run_exact_case "linux cpu no subcommand" 2 "$BIN" linux cpu
run_exact_case "linux cpu unknown subcommand" 2 "$BIN" linux cpu bogus

# cpu list reports the host ISA and applicable fuzz mode; runs on any host and
# never executes code.
run_exact_case "linux cpu list" 0 "$BIN" linux cpu list
run_exact_case "linux cpu list --help" 0 "$BIN" linux cpu list --help
run_exact_case "linux cpu list extra arg" 2 "$BIN" linux cpu list extra

# Argument validation happens before any code execution.
run_exact_case "linux cpu fuzz bad --mode" 2 "$BIN" linux cpu fuzz --mode bogus
run_exact_case "linux cpu fuzz bad --length" 2 "$BIN" linux cpu fuzz --length 99
# A stray positional is rejected before any code execution.
run_exact_case "linux cpu fuzz extra arg" 2 "$BIN" linux cpu fuzz extra

# The offline engine self-test exercises generation/classification/reserved
# tables across ISAs without executing any candidate.
run_exact_case "linux cpu fuzz --selftest" 0 "$BIN" linux cpu fuzz --selftest

# --show decodes a finding file offline (no execution, host-independent); ISA
# read from header.
FINDING_FILE="$(mktemp /tmp/ela-cpu-finding.XXXXXX)"
printf '# target=cpu-aarch64-le mode=sweep\n' > "$FINDING_FILE"
printf '0b000000 executed exec_len=4 note=custom-opcode\n' >> "$FINDING_FILE"
run_exact_case "linux cpu fuzz --show (infer ISA)" 0 "$BIN" linux cpu fuzz --show "$FINDING_FILE"

# A finding file for a non-host ISA cannot be replayed (would execute a foreign
# ISA); it must be rejected before any execution. Use an ISA the fuzzer does not
# support (sparc64) so it is foreign to EVERY test runner -- the CI qemu matrix
# covers every supported ISA (incl. powerpc64/riscv/mips/...), so a supported
# ISA would match some runner's host and wrongly execute instead of rejecting.
FOREIGN_FILE="$(mktemp /tmp/ela-cpu-foreign.XXXXXX)"
printf '# target=cpu-sparc64 mode=sweep\n' > "$FOREIGN_FILE"
printf '7fe00008 executed exec_len=4\n' >> "$FOREIGN_FILE"
run_exact_case "linux cpu fuzz --replay foreign ISA" 2 "$BIN" linux cpu fuzz --replay "$FOREIGN_FILE"
rm -f "$FINDING_FILE" "$FOREIGN_FILE"

finish_tests
