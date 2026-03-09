#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$REPO_ROOT/uboot_audit"

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"
TEST_OUTPUT_HTTPS="${TEST_OUTPUT_HTTPS:-}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-http)
            if [ "$#" -lt 2 ]; then
                echo "error: --output-http requires a value"
                exit 2
            fi
            TEST_OUTPUT_HTTP="$2"
            shift 2
            ;;
        --output-http=*)
            TEST_OUTPUT_HTTP="${1#*=}"
            shift
            ;;
        --output-https)
            if [ "$#" -lt 2 ]; then
                echo "error: --output-https requires a value"
                exit 2
            fi
            TEST_OUTPUT_HTTPS="$2"
            shift 2
            ;;
        --output-https=*)
            TEST_OUTPUT_HTTPS="${1#*=}"
            shift
            ;;
        *)
            echo "error: unknown argument: $1"
            exit 2
            ;;
    esac
done

if [ -n "$TEST_OUTPUT_HTTP" ] && [ -n "$TEST_OUTPUT_HTTPS" ]; then
    echo "error: set only one of --output-http or --output-https"
    exit 2
fi

export TEST_OUTPUT_HTTP
export TEST_OUTPUT_HTTPS

# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "dmesg subcommand argument coverage"

run_exact_case "dmesg --help" 0 "$BIN" dmesg --help
run_accept_case "dmesg" "$BIN" dmesg
run_accept_case "dmesg --verbose" "$BIN" dmesg --verbose
run_exact_case "dmesg --output-tcp + --help" 0 "$BIN" dmesg --output-tcp 127.0.0.1:9 --help
run_accept_case "dmesg --output-http" "$BIN" dmesg --output-http http://127.0.0.1:1/dmesg
run_accept_case "dmesg --output-https" "$BIN" dmesg --output-https https://127.0.0.1:1/dmesg
run_accept_case "dmesg --insecure" "$BIN" dmesg --insecure

run_accept_case "dmesg with --output-format txt" "$BIN" --output-format txt dmesg
run_accept_case "dmesg with --output-format csv" "$BIN" --output-format csv dmesg
run_accept_case "dmesg with --output-format json" "$BIN" --output-format json dmesg

log="$(mktemp /tmp/test_dmesg_warn.XXXXXX)"
run_with_output_override "$BIN" --output-format json dmesg --help >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q "Warning: --output-format has no effect for dmesg" "$log"; then
    echo "[PASS] dmesg warns when --output-format is set"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] dmesg warns when --output-format is set (rc=$rc)"
    sed -n '1,80p' "$log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

finish_tests