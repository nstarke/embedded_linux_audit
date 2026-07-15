#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux bt fuzz subcommand argument coverage"

run_exact_case "linux bt fuzz --help" 0 "$BIN" linux bt fuzz --help
run_exact_case "linux bt fuzz -h" 0 "$BIN" linux bt fuzz -h
run_exact_case "linux bt no subcommand" 2 "$BIN" linux bt
run_exact_case "linux bt unknown subcommand" 2 "$BIN" linux bt bogus

# bt list enumerates controllers from sysfs; runs on any host (prints rows or
# "No Bluetooth controllers found") and never needs hardware.
run_exact_case "linux bt list" 0 "$BIN" linux bt list
run_exact_case "linux bt list --help" 0 "$BIN" linux bt list --help
run_exact_case "linux bt list extra arg" 2 "$BIN" linux bt list extra
run_exact_case "linux bt fuzz missing target" 2 "$BIN" linux bt fuzz
run_exact_case "linux bt fuzz unknown target" 2 "$BIN" linux bt fuzz --target bogus
run_exact_case "linux bt fuzz extra arg" 2 "$BIN" linux bt fuzz --target hci-generic --hci hci0 extra
run_exact_case "linux bt fuzz bad probe-every" 2 "$BIN" linux bt fuzz --target hci-generic --probe-every 0

# A malformed controller name is rejected before any socket is opened.
run_exact_case "linux bt fuzz bad --hci" 2 "$BIN" linux bt fuzz --target hci-generic --hci nothci

# The offline engine self-test exercises the shared engine + HCI grammar.
run_exact_case "linux bt fuzz --selftest" 0 "$BIN" linux bt fuzz --selftest

# --show decodes a crash file offline (no hardware); target read from header.
CRASH_FILE="$(mktemp /tmp/ela-bt-crash.XXXXXX)"
printf '# target=hci-generic cases=1\n' > "$CRASH_FILE"
printf 'LE_SET_ADV_DATA 0820200aff00112233445566 # adv_len=len\n' >> "$CRASH_FILE"
run_exact_case "linux bt fuzz --show (infer target)" 0 "$BIN" linux bt fuzz --show "$CRASH_FILE"
rm -f "$CRASH_FILE"

finish_tests
