#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"

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
		*)
			echo "error: unknown argument: $1"
			exit 2
			;;
	esac
done

export TEST_OUTPUT_HTTP

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux tpm2 subcommand argument coverage"

run_exact_case "linux tpm2 --help" 0 "$BIN" linux tpm2 --help
run_exact_case "linux tpm2 no args" 2 "$BIN" linux tpm2
run_exact_case "linux tpm2 list-commands extra arg" 2 "$BIN" linux tpm2 list-commands extra

log="$(mktemp /tmp/test_linux_tpm2_list_commands.XXXXXX)"
"$BIN" linux tpm2 list-commands >"$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -q '^createprimary$' "$log" && \
   grep -q '^getcap$' "$log" && \
   grep -q '^nvreadpublic$' "$log" && \
   grep -q '^pcrread$' "$log"; then
    echo "[PASS] linux tpm2 list-commands enumerates built-in TPM2 commands"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux tpm2 list-commands enumerates built-in TPM2 commands (rc=$rc)"
    print_file_head_scrubbed "$log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$log"

run_exact_case "linux tpm2 getcap --help" 0 "$BIN" linux tpm2 getcap --help
run_exact_case "linux tpm2 pcrread --help" 0 "$BIN" linux tpm2 pcrread --help
run_exact_case "linux tpm2 nvreadpublic --help" 0 "$BIN" linux tpm2 nvreadpublic --help
run_exact_case "linux tpm2 createprimary --help" 0 "$BIN" linux tpm2 createprimary --help
run_exact_case "linux tpm2 unsupported command" 2 "$BIN" linux tpm2 not-a-command

finish_tests
