#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "arch subcommand argument coverage"

# ---------------------------------------------------------------------------
# Help / usage
# ---------------------------------------------------------------------------
run_exact_case "arch --help"      0 "$BIN" arch --help
run_exact_case "arch -h"          0 "$BIN" arch -h
run_exact_case "arch help"        0 "$BIN" arch help
run_exact_case "arch (no args)"   0 "$BIN" arch
run_exact_case "arch unknown sub" 2 "$BIN" arch unknown-subcommand

# ---------------------------------------------------------------------------
# Default (txt) format — basic exit code checks
# ---------------------------------------------------------------------------
run_exact_case "arch bit exits 0"         0 "$BIN" arch bit
run_exact_case "arch isa exits 0"         0 "$BIN" arch isa
run_exact_case "arch endianness exits 0"  0 "$BIN" arch endianness

# ---------------------------------------------------------------------------
# arch bit: output must be exactly "32" or "64"
# ---------------------------------------------------------------------------
bit_out="$("$BIN" arch bit 2>/dev/null)"
case "$bit_out" in
    32|64)
        echo "[PASS] arch bit output is valid: $bit_out"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
        ;;
    *)
        echo "[FAIL] arch bit output is not 32 or 64: '$bit_out'"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        ;;
esac

# ---------------------------------------------------------------------------
# arch isa: output must be a known ISA name
# ---------------------------------------------------------------------------
isa_out="$("$BIN" arch isa 2>/dev/null)"
case "$isa_out" in
    x86|x86_64|arm32|aarch64|mips|mips64|powerpc|powerpc64|riscv32|riscv64)
        echo "[PASS] arch isa output is a known ISA: $isa_out"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
        ;;
    *)
        echo "[FAIL] arch isa output is not a recognised ISA name: '$isa_out'"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        ;;
esac

# ---------------------------------------------------------------------------
# arch endianness: output must be exactly "big" or "little"
# ---------------------------------------------------------------------------
end_out="$("$BIN" arch endianness 2>/dev/null)"
case "$end_out" in
    big|little)
        echo "[PASS] arch endianness output is valid: $end_out"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
        ;;
    *)
        echo "[FAIL] arch endianness output is not 'big' or 'little': '$end_out'"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        ;;
esac

# ---------------------------------------------------------------------------
# Cross-check: arch bit is consistent with the ISA name for ISAs that encode
# their width explicitly (x86_64, mips64, powerpc64, riscv64, riscv32, etc.)
# ---------------------------------------------------------------------------
case "$isa_out" in
    x86_64|mips64|powerpc64|riscv64|aarch64)
        if [ "$bit_out" = "64" ]; then
            echo "[PASS] arch bit=64 consistent with 64-bit ISA $isa_out"
            PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
        else
            echo "[FAIL] arch bit=$bit_out but ISA $isa_out implies 64-bit"
            FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        fi
        ;;
    x86|arm32|mips|powerpc|riscv32)
        if [ "$bit_out" = "32" ]; then
            echo "[PASS] arch bit=32 consistent with 32-bit ISA $isa_out"
            PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
        else
            echo "[FAIL] arch bit=$bit_out but ISA $isa_out implies 32-bit"
            FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# --output-format json: each subcommand must emit valid JSON with correct keys
# ---------------------------------------------------------------------------
run_exact_case "arch bit --output-format json exits 0" \
    0 "$BIN" --output-format json arch bit
run_exact_case "arch isa --output-format json exits 0" \
    0 "$BIN" --output-format json arch isa
run_exact_case "arch endianness --output-format json exits 0" \
    0 "$BIN" --output-format json arch endianness

for sub in bit isa endianness; do
    json_out="$("$BIN" --output-format json arch "$sub" 2>/dev/null)"
    # Must contain "record":"arch"
    case "$json_out" in
        *'"record":"arch"'*)
            echo "[PASS] arch $sub json contains record=arch"
            PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
            ;;
        *)
            echo "[FAIL] arch $sub json missing record=arch: $json_out"
            FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
            ;;
    esac
    # Must contain "subcommand":"<sub>"
    case "$json_out" in
        *"\"subcommand\":\"$sub\""*)
            echo "[PASS] arch $sub json contains subcommand=$sub"
            PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
            ;;
        *)
            echo "[FAIL] arch $sub json missing subcommand=$sub: $json_out"
            FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
            ;;
    esac
    # Must contain "value":
    case "$json_out" in
        *'"value":'*)
            echo "[PASS] arch $sub json contains value field"
            PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
            ;;
        *)
            echo "[FAIL] arch $sub json missing value field: $json_out"
            FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# --output-format csv: output must match the txt value (no special chars)
# ---------------------------------------------------------------------------
run_exact_case "arch bit --output-format csv exits 0" \
    0 "$BIN" --output-format csv arch bit
run_exact_case "arch isa --output-format csv exits 0" \
    0 "$BIN" --output-format csv arch isa
run_exact_case "arch endianness --output-format csv exits 0" \
    0 "$BIN" --output-format csv arch endianness

for sub in bit isa endianness; do
    txt_val="$("$BIN" arch "$sub" 2>/dev/null)"
    csv_val="$("$BIN" --output-format csv arch "$sub" 2>/dev/null)"
    # csv_write may quote the field; strip outer double-quotes before comparing
    stripped_csv="$(printf '%s' "$csv_val" | sed 's/^"//;s/"$//')"
    if [ "$txt_val" = "$stripped_csv" ]; then
        echo "[PASS] arch $sub csv value matches txt: $txt_val"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] arch $sub csv '$stripped_csv' != txt '$txt_val'"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
done

# ---------------------------------------------------------------------------
# --output-format with invalid value must fail with rc=2
# ---------------------------------------------------------------------------
run_exact_case "arch bit invalid --output-format" \
    2 "$BIN" --output-format xml arch bit

# ---------------------------------------------------------------------------
# Remote output: unreachable HTTP endpoint must not crash (accept rc != 2)
# ---------------------------------------------------------------------------
run_accept_case "arch bit --output-http unreachable" \
    "$BIN" --output-http http://127.0.0.1:1 arch bit
run_accept_case "arch isa --output-http unreachable" \
    "$BIN" --output-http http://127.0.0.1:1 arch isa
run_accept_case "arch endianness --output-http unreachable" \
    "$BIN" --output-http http://127.0.0.1:1 arch endianness

finish_tests
