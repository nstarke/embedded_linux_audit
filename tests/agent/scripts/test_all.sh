#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SCRIPT_DIR/../shell/common.sh"

require_binary "$BIN"
print_section "agent script coverage"

echo "Tracking per-script sub-test results"

test_list="$(mktemp /tmp/agent_script_tests.XXXXXX)"
trap 'rm -f "$test_list"' EXIT HUP INT TERM

find "$SCRIPT_DIR" -type f -name '*.ela' | sort >"$test_list"

while IFS= read -r test_script; do
    relative_name="${test_script#"$SCRIPT_DIR"/}"
    run_accept_case "script $relative_name" "$BIN" --script "$test_script"
done <"$test_list"

finish_tests