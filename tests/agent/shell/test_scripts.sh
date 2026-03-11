#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"
SCRIPTS_DIR="$SCRIPT_DIR/../scripts"

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"

# shellcheck source=tests/agent/shell/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "interactive script file coverage"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-http)
            if [ "$#" -lt 2 ]; then
                echo "error: --output-http requires a value"
                echo "usage: $0 [--output-http <url>]"
                exit 2
            fi
            TEST_OUTPUT_HTTP="$2"
            shift 2
            ;;
        --output-http=*)
            TEST_OUTPUT_HTTP="${1#*=}"
            shift
            ;;
        *)
            echo "error: unknown argument: $1"
            echo "usage: $0 [--output-http <url>]"
            exit 2
            ;;
    esac
done

for test_script in \
    "$SCRIPTS_DIR/test_efi_dump_vars_args.ela" \
    "$SCRIPTS_DIR/test_linux_dmesg_args.ela" \
    "$SCRIPTS_DIR/test_linux_download_file_args.ela" \
    "$SCRIPTS_DIR/test_linux_execute_command_args.ela" \
    "$SCRIPTS_DIR/test_linux_grep_args.ela" \
    "$SCRIPTS_DIR/test_linux_list_files_args.ela" \
    "$SCRIPTS_DIR/test_linux_list_symlinks_args.ela" \
    "$SCRIPTS_DIR/test_linux_remote_copy_args.ela" \
    "$SCRIPTS_DIR/test_efi_bios_orom_args.ela" \
    "$SCRIPTS_DIR/test_uboot_audit_args.ela" \
    "$SCRIPTS_DIR/test_uboot_image_args.ela" \
    "$SCRIPTS_DIR/test_uboot_env_args.ela"
do
    run_accept_case "script $(basename "$test_script")" "$BIN" --script "$test_script"
done

finish_tests