#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux modules subcommand argument coverage"

run_exact_case "linux modules --help" 0 "$BIN" linux modules --help
run_exact_case "linux modules list --help" 0 "$BIN" linux modules list --help
run_accept_case "linux modules list" "$BIN" linux modules list
run_accept_case "linux modules list json" "$BIN" --output-format json linux modules list
run_accept_case "linux modules list csv" "$BIN" --output-format csv linux modules list
run_exact_case "linux modules no action" 0 "$BIN" linux modules
run_exact_case "linux modules unknown action" 2 "$BIN" linux modules reload demo
run_exact_case "linux modules list extra arg" 2 "$BIN" linux modules list extra
run_exact_case "linux modules load missing path" 2 "$BIN" linux modules load
run_exact_case "linux modules load missing file" 1 "$BIN" linux modules load /tmp/definitely-missing-ela-module.ko
run_exact_case "linux modules load --force missing file" 1 "$BIN" linux modules load --force /tmp/definitely-missing-ela-module.ko
run_exact_case "linux modules unload missing name" 2 "$BIN" linux modules unload
run_exact_case "linux modules unload extra arg" 2 "$BIN" linux modules unload demo extra

finish_tests
