#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux pcap subcommand argument coverage"

run_exact_case "linux pcap --help" 0 "$BIN" linux pcap --help
run_exact_case "linux pcap missing interface" 2 "$BIN" linux pcap
run_exact_case "linux pcap extra arg" 2 "$BIN" linux pcap --interface lo extra
run_exact_case "linux pcap stream-to-host without output-http" 2 "$BIN" linux pcap --interface lo --stream-to-host
run_accept_case "linux pcap output-format warning" "$BIN" --output-format json linux pcap --help

run_exact_case "linux pcap replay --help" 0 "$BIN" linux pcap replay --help
run_exact_case "linux pcap replay missing file" 2 "$BIN" linux pcap replay --interface lo
run_exact_case "linux pcap replay missing interface" 2 "$BIN" linux pcap replay /tmp/does_not_exist.pcap
run_exact_case "linux pcap replay extra arg" 2 "$BIN" linux pcap replay /tmp/a.pcap extra --interface lo

finish_tests
