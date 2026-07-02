#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux netstat subcommand argument coverage"

run_exact_case "linux netstat --help" 0 "$BIN" linux netstat --help
run_exact_case "linux netstat extra arg" 2 "$BIN" linux netstat extra
run_accept_case "linux netstat output-format warning" "$BIN" --output-format json linux netstat --help

run_accept_case "linux netstat reads /proc socket tables" "$BIN" linux netstat

finish_tests
