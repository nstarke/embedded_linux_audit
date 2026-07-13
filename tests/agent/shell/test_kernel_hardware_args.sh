#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$SCRIPT_DIR"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "kernel-backed hardware argument coverage"

run_exact_case "spi --help" 0 "$BIN" spi --help
run_exact_case "spi unknown command" 2 "$BIN" spi probe
run_exact_case "spi list extra argument" 2 "$BIN" spi list extra
run_exact_case "spi dump missing path" 2 "$BIN" spi dump
run_exact_case "spi dump invalid index" 2 "$BIN" spi dump /tmp/unused -1

run_exact_case "nand --help" 0 "$BIN" nand --help
run_exact_case "nand unknown command" 2 "$BIN" nand chip
run_exact_case "nand flash --help" 0 "$BIN" nand flash --help
run_exact_case "nand flash unknown action" 2 "$BIN" nand flash probe
run_exact_case "nand flash list extra argument" 2 "$BIN" nand flash list extra
run_exact_case "nand flash dump missing path" 2 "$BIN" nand flash dump
run_exact_case "nand flash dump invalid index" 2 "$BIN" nand flash dump /tmp/unused -1

run_exact_case "emmc --help" 0 "$BIN" emmc --help
run_exact_case "emmc unknown command" 2 "$BIN" emmc probe
run_exact_case "emmc list extra argument" 2 "$BIN" emmc list extra
run_exact_case "emmc dump missing path" 2 "$BIN" emmc dump
run_exact_case "emmc dump invalid index" 2 "$BIN" emmc dump /tmp/unused -1

run_exact_case "orom --help" 0 "$BIN" orom --help
run_exact_case "orom unknown command" 2 "$BIN" orom probe
run_exact_case "orom list extra argument" 2 "$BIN" orom list extra
run_exact_case "orom dump missing path" 2 "$BIN" orom dump
run_exact_case "orom dump invalid index" 2 "$BIN" orom dump /tmp/unused -1

run_exact_case "usb --help" 0 "$BIN" usb --help
run_exact_case "usb unknown command" 2 "$BIN" usb probe
run_exact_case "usb reset invalid index" 2 "$BIN" usb reset -1
run_exact_case "usb port unknown action" 2 "$BIN" usb port probe 0
run_exact_case "usb port reset invalid index" 2 "$BIN" usb port reset -1
run_exact_case "usb descriptor missing dump" 2 "$BIN" usb descriptor probe /tmp/unused
run_exact_case "usb descriptor invalid index" 2 "$BIN" usb descriptor dump /tmp/unused -1
run_exact_case "usb pcap missing path" 2 "$BIN" usb pcap
run_exact_case "usb pcap invalid bus" 2 "$BIN" usb pcap /tmp/unused -1

# Valid commands must reach the runtime module-open failure, not be rejected
# as usage errors. The module device is intentionally absent in CI.
run_exact_case "spi list missing module" 1 "$BIN" spi list
run_exact_case "nand flash list missing module" 1 "$BIN" nand flash list
run_exact_case "emmc list missing module" 1 "$BIN" emmc list
run_exact_case "orom list missing module" 1 "$BIN" orom list
run_exact_case "usb list missing module" 1 "$BIN" usb list

finish_tests
