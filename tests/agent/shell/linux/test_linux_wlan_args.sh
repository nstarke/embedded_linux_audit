#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux wlan fuzz subcommand argument coverage"

run_exact_case "linux wlan fuzz --help" 0 "$BIN" linux wlan fuzz --help
run_exact_case "linux wlan fuzz -h" 0 "$BIN" linux wlan fuzz -h
run_exact_case "linux wlan no subcommand" 2 "$BIN" linux wlan
run_exact_case "linux wlan unknown subcommand" 2 "$BIN" linux wlan bogus

# wlan list enumerates NICs from sysfs; runs on any host (prints rows or
# "No WLAN interfaces found") and never needs hardware or the module.
run_exact_case "linux wlan list" 0 "$BIN" linux wlan list
run_exact_case "linux wlan list --help" 0 "$BIN" linux wlan list --help
run_exact_case "linux wlan list extra arg" 2 "$BIN" linux wlan list extra
run_exact_case "linux wlan fuzz missing target" 2 "$BIN" linux wlan fuzz
run_exact_case "linux wlan fuzz unknown target" 2 "$BIN" linux wlan fuzz --target bogus
run_exact_case "linux wlan fuzz extra arg" 2 "$BIN" linux wlan fuzz --target ath9k-htc extra
run_exact_case "linux wlan fuzz bad probe-every" 2 "$BIN" linux wlan fuzz --target ath9k-htc --probe-every 0

# The offline engine self-test exercises the mutator, renderer, and triage
# loop with a mock transport -- no hardware required, must pass everywhere.
run_exact_case "linux wlan fuzz --selftest" 0 "$BIN" linux wlan fuzz --selftest

# --show decodes a crash file offline (no hardware); target is read from the
# file's "# target=" header when --target is omitted.
CRASH_FILE="$(mktemp /tmp/ela-wlan-crash.XXXXXX)"
printf '# target=ath10k cases=1\n' > "$CRASH_FILE"
printf 'VDEV_DELETE 08000000 # vdev_id=idx:8\n' >> "$CRASH_FILE"
run_exact_case "linux wlan fuzz --show (infer target)" 0 "$BIN" linux wlan fuzz --show "$CRASH_FILE"
run_exact_case "linux wlan fuzz --show --target" 0 "$BIN" linux wlan fuzz --show "$CRASH_FILE" --target ath10k

NOHDR_FILE="$(mktemp /tmp/ela-wlan-nohdr.XXXXXX)"
printf 'VDEV_DELETE 08000000 #\n' > "$NOHDR_FILE"
run_exact_case "linux wlan fuzz --show headerless no target" 2 "$BIN" linux wlan fuzz --show "$NOHDR_FILE"
rm -f "$CRASH_FILE" "$NOHDR_FILE"

finish_tests
