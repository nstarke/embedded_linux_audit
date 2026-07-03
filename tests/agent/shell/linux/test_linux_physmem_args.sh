#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux memread/memwrite argument coverage"

run_exact_case "linux memread --help" 0 "$BIN" linux memread --help
run_exact_case "linux memwrite --help" 0 "$BIN" linux memwrite --help
run_exact_case "linux mmio --help" 0 "$BIN" linux mmio --help
run_exact_case "linux pci --help" 0 "$BIN" linux pci --help
run_exact_case "linux physmem --help" 0 "$BIN" linux physmem --help
run_exact_case "linux mmio read misaligned" 2 "$BIN" linux mmio read 0xfe000002 4
run_exact_case "linux mmio read bad width" 2 "$BIN" linux mmio read 0xfe000000 3
run_exact_case "linux mmio write value too big" 2 "$BIN" linux mmio write 0xfe000000 1 0x100
run_exact_case "linux mmio unknown action" 2 "$BIN" linux mmio poke 0xfe000000 4
run_exact_case "linux pci read bad bdf" 2 "$BIN" linux pci read nope 0 4
run_exact_case "linux pci read bad offset" 2 "$BIN" linux pci read 00:1f.3 4096 4
run_exact_case "linux pci read bad width" 2 "$BIN" linux pci read 00:1f.3 0 8
run_exact_case "linux physmem alloc zero" 2 "$BIN" linux physmem alloc 0
run_exact_case "linux physmem free missing addr" 2 "$BIN" linux physmem free
run_exact_case "linux physmem unknown action" 2 "$BIN" linux physmem defrag
run_exact_case "linux memread missing length" 2 "$BIN" linux memread 0x1000
run_exact_case "linux memread bad address" 2 "$BIN" linux memread nope 16
run_exact_case "linux memread zero length" 2 "$BIN" linux memread 0x1000 0
run_exact_case "linux memread extra arg" 2 "$BIN" linux memread 0x1000 16 extra
run_exact_case "linux memread unknown option" 2 "$BIN" linux memread --wat 0x1000 16
run_exact_case "linux memwrite missing data" 2 "$BIN" linux memwrite 0x1000
run_exact_case "linux memwrite bad hex" 1 "$BIN" linux memwrite 0x1000 zz

# Valid args but the device node is absent (module not loaded): a clear
# runtime failure, not a usage error. Point the device override somewhere
# that never exists so the case is deterministic even on hosts that DO have
# the real module loaded.
ELA_PHYSMEM_DEVICE="/tmp/ela-definitely-missing-physmem-node"
export ELA_PHYSMEM_DEVICE
missing_dev_log="$(mktemp /tmp/test_linux_physmem.XXXXXX)"
"$BIN" linux memread 0x1000 16 >"$missing_dev_log" 2>&1
rc=$?
if [ "$rc" -eq 1 ] && grep -q "is the ela_kmod module loaded" "$missing_dev_log"; then
    echo "[PASS] linux memread reports missing device node"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux memread reports missing device node (rc=$rc)"
    print_file_head_scrubbed "$missing_dev_log" 20
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$missing_dev_log"
run_exact_case "linux memwrite missing device" 1 "$BIN" linux memwrite 0x1000 deadbeef
run_exact_case "linux mmio read missing device" 1 "$BIN" linux mmio read 0xfe000000 4
run_exact_case "linux pci read missing device" 1 "$BIN" linux pci read 00:1f.3 0 4
run_exact_case "linux physmem alloc missing device" 1 "$BIN" linux physmem alloc 4096
unset ELA_PHYSMEM_DEVICE

finish_tests
