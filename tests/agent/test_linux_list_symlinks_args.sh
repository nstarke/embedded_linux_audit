#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BIN="/tmp/embedded_linux_audit"

# shellcheck source=tests/agent/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "linux list-symlinks subcommand argument coverage"

TEST_DISABLE_OUTPUT_OVERRIDE=1
export TEST_DISABLE_OUTPUT_OVERRIDE

TMP_DIR="$(mktemp -d /tmp/test_list_symlinks_args.XXXXXX)"
TMP_SUBDIR="$TMP_DIR/subdir"
TMP_FILE="$TMP_DIR/plain.txt"
TMP_LINK_TOP="$TMP_DIR/top-link"
TMP_LINK_SUB="$TMP_SUBDIR/nested-link"
mkdir -p "$TMP_SUBDIR"
printf 'plain\n' >"$TMP_FILE"
ln -s /tmp/target-top "$TMP_LINK_TOP"
ln -s ../plain.txt "$TMP_LINK_SUB"

run_exact_case "linux list-symlinks --help" 0 "$BIN" --verbose linux list-symlinks --help
run_exact_case "linux list-symlinks relative path" 2 "$BIN" --verbose linux list-symlinks ./relative
run_exact_case "linux list-symlinks file path" 2 "$BIN" --verbose linux list-symlinks "$TMP_FILE"
run_exact_case "linux list-symlinks invalid --output-http" 2 "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-http ftp://127.0.0.1:1/symlink-list
run_exact_case "linux list-symlinks invalid --output-https" 2 "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-https http://127.0.0.1:1/symlink-list
run_exact_case "linux list-symlinks both http+https" 2 "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-http http://127.0.0.1:1/symlink-list --output-https https://127.0.0.1:1/symlink-list
run_exact_case "linux list-symlinks extra positional argument" 2 "$BIN" --verbose linux list-symlinks "$TMP_DIR" /tmp/extra

run_exact_case "linux list-symlinks no directory argument defaults to /" 0 "$BIN" --verbose linux list-symlinks
run_exact_case "linux list-symlinks default directory" 0 "$BIN" --verbose linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks --recursive" 0 "$BIN" --verbose linux list-symlinks "$TMP_DIR" --recursive
run_accept_case "linux list-symlinks --output-http" "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-http http://127.0.0.1:1/symlink-list
run_accept_case "linux list-symlinks --output-https" "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-https https://127.0.0.1:1/symlink-list
run_accept_case "linux list-symlinks --output-https --insecure" "$BIN" --verbose linux list-symlinks "$TMP_DIR" --output-https https://127.0.0.1:1/symlink-list --insecure
run_exact_case "linux list-symlinks with --output-format txt" 0 "$BIN" --output-format txt --verbose linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks with --output-format csv" 0 "$BIN" --output-format csv --verbose linux list-symlinks "$TMP_DIR"
run_exact_case "linux list-symlinks with --output-format json" 0 "$BIN" --output-format json --verbose linux list-symlinks "$TMP_DIR"

txt_log="$(mktemp /tmp/test_list_symlinks_txt.XXXXXX)"
"$BIN" --output-format txt --verbose linux list-symlinks "$TMP_DIR" >"$txt_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -Fxq "$TMP_LINK_TOP -> /tmp/target-top" "$txt_log" && ! grep -Fqx "$TMP_LINK_SUB -> ../plain.txt" "$txt_log"; then
    echo "[PASS] linux list-symlinks default listing stays non-recursive"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks default listing stays non-recursive (rc=$rc)"
    sed -n '1,80p' "$txt_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$txt_log"

recursive_log="$(mktemp /tmp/test_list_symlinks_recursive.XXXXXX)"
"$BIN" --output-format txt --verbose linux list-symlinks "$TMP_DIR" --recursive >"$recursive_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -Fxq "$TMP_LINK_TOP -> /tmp/target-top" "$recursive_log" && grep -Fxq "$TMP_LINK_SUB -> ../plain.txt" "$recursive_log"; then
    echo "[PASS] linux list-symlinks --recursive includes nested symlinks"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks --recursive includes nested symlinks (rc=$rc)"
    sed -n '1,80p' "$recursive_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$recursive_log"

csv_log="$(mktemp /tmp/test_list_symlinks_csv.XXXXXX)"
"$BIN" --output-format csv --verbose linux list-symlinks "$TMP_DIR" >"$csv_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -Fxq "\"$TMP_LINK_TOP\",\"/tmp/target-top\"" "$csv_log"; then
    echo "[PASS] linux list-symlinks csv output matches expected format"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks csv output matches expected format (rc=$rc)"
    sed -n '1,80p' "$csv_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$csv_log"

json_log="$(mktemp /tmp/test_list_symlinks_json.XXXXXX)"
"$BIN" --output-format json --verbose linux list-symlinks "$TMP_DIR" >"$json_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -Fxq "{\"link_path\":\"$TMP_LINK_TOP\",\"location_path\":\"/tmp/target-top\"}" "$json_log"; then
    echo "[PASS] linux list-symlinks json output matches expected format"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks json output matches expected format (rc=$rc)"
    sed -n '1,80p' "$json_log"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$json_log"

rm -rf "$TMP_DIR"
finish_tests