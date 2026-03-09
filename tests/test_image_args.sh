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
print_section "image subcommand argument coverage"

run_exact_case "image --help" 0 "$BIN" image --help
run_accept_case "image --output-format txt" "$BIN" --output-format txt image --verbose
run_accept_case "image --output-format csv" "$BIN" --output-format csv image --verbose
run_accept_case "image --output-format json" "$BIN" --output-format json image --verbose
run_accept_case "image --verbose" "$BIN" image --verbose
run_accept_case "image --dev" "$BIN" image --dev /dev/null
run_accept_case "image --step" "$BIN" image --step 0x1000
run_accept_case "image --allow-text" "$BIN" image --allow-text
run_accept_case "image --allow-text=<text>" "$BIN" image --allow-text=BootROM
run_accept_case "image --allow-text <text>" "$BIN" image --allow-text BootROM
run_accept_case "image --skip-remove" "$BIN" image --skip-remove
run_accept_case "image --skip-mtd" "$BIN" image --skip-mtd
run_accept_case "image --skip-ubi" "$BIN" image --skip-ubi
run_accept_case "image --skip-sd" "$BIN" image --skip-sd
run_accept_case "image --skip-emmc" "$BIN" image --skip-emmc
run_accept_case "image --insecure" "$BIN" image --insecure

run_accept_case "image --find-address + --offset" \
    "$BIN" image --find-address --dev /dev/null --offset 0x0

run_accept_case "image --list-commands + --offset" \
    "$BIN" image --list-commands --dev /dev/null --offset 0x0

run_accept_case "image --send-logs + --output-tcp" \
    "$BIN" image --verbose --send-logs --output-tcp 127.0.0.1:9

run_accept_case "image --pull + --output-tcp" \
    "$BIN" image --pull --dev /dev/null --offset 0x0 --output-tcp 127.0.0.1:9

run_accept_case "image --pull + --output-http" \
    "$BIN" image --pull --dev /dev/null --offset 0x0 --output-http http://127.0.0.1:1/image

run_accept_case "image --pull + --output-https" \
    "$BIN" image --pull --dev /dev/null --offset 0x0 --output-https https://127.0.0.1:1/image

help_log="$(mktemp /tmp/test_image_help.XXXXXX)"
run_with_output_override "$BIN" image --help >"$help_log" 2>&1
if grep -q "/dev/mtd\*" "$help_log"; then
    echo "[FAIL] image --help should not advertise /dev/mtd* scan targets"
    sed -n '1,80p' "$help_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
else
    echo "[PASS] image --help only advertises /dev/mtdblock* for MTD scans"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
fi
rm -f "$help_log"

finish_tests
