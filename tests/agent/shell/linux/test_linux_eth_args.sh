#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux eth fuzz subcommand argument coverage"

run_exact_case "linux eth fuzz --help" 0 "$BIN" linux eth fuzz --help
run_exact_case "linux eth fuzz -h" 0 "$BIN" linux eth fuzz -h
run_exact_case "linux eth no subcommand" 2 "$BIN" linux eth
run_exact_case "linux eth unknown subcommand" 2 "$BIN" linux eth bogus

# eth list enumerates NICs from sysfs; runs on any host (prints rows or
# "No ethernet NICs found") and never needs hardware or the module.
run_exact_case "linux eth list" 0 "$BIN" linux eth list
run_exact_case "linux eth list --help" 0 "$BIN" linux eth list --help
run_exact_case "linux eth list extra arg" 2 "$BIN" linux eth list extra
run_exact_case "linux eth fuzz missing target" 2 "$BIN" linux eth fuzz
run_exact_case "linux eth fuzz unknown target" 2 "$BIN" linux eth fuzz --target bogus
run_exact_case "linux eth fuzz extra arg" 2 "$BIN" linux eth fuzz --target ethtool-generic --iface eth0 extra
run_exact_case "linux eth fuzz bad probe-every" 2 "$BIN" linux eth fuzz --target ethtool-generic --iface eth0 --probe-every 0

# ethtool-generic needs an interface for a hardware run; malformed names are
# rejected. Both fail before opening a socket, so safe on any host.
run_exact_case "linux eth fuzz ethtool-generic missing --iface" 2 "$BIN" linux eth fuzz --target ethtool-generic
run_exact_case "linux eth fuzz ethtool-generic bad --iface" 2 "$BIN" linux eth fuzz --target ethtool-generic --iface "eth/0"

# The offline engine self-test exercises the shared NIC-fuzz engine + all
# ethernet grammars; no hardware required, must pass everywhere.
run_exact_case "linux eth fuzz --selftest" 0 "$BIN" linux eth fuzz --selftest

# --show decodes a crash file offline (no hardware); target read from the
# file's "# target=" header when --target is omitted.
CRASH_FILE="$(mktemp /tmp/ela-eth-crash.XXXXXX)"
printf '# target=ethtool-generic cases=1\n' > "$CRASH_FILE"
printf 'GEEPROM 0b00000000ffffff00 # len=128\n' >> "$CRASH_FILE"
run_exact_case "linux eth fuzz --show (infer target)" 0 "$BIN" linux eth fuzz --show "$CRASH_FILE"
rm -f "$CRASH_FILE"

finish_tests
