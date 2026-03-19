#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux filesystem integration coverage"

TMP_DIR="$(mktemp -d /tmp/ela_linux_fs_integration.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

TOP_FILE="$TMP_DIR/top.txt"
NESTED_DIR="$TMP_DIR/nested"
NESTED_FILE="$NESTED_DIR/child.txt"
OTHER_FILE="$NESTED_DIR/other.txt"
SUID_FILE="$TMP_DIR/suid.sh"
SYMLINK_FILE="$TMP_DIR/top.link"

mkdir -p "$NESTED_DIR"
printf 'needle top\nplain line\n' >"$TOP_FILE"
printf 'nested needle line\n' >"$NESTED_FILE"
printf 'no match here\n' >"$OTHER_FILE"
printf '#!/bin/sh\necho suid\n' >"$SUID_FILE"
chmod 4755 "$SUID_FILE"
ln -s "$TOP_FILE" "$SYMLINK_FILE"

list_log="$(mktemp /tmp/ela_list_files_integration.XXXXXX)"
TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" linux list-files "$TMP_DIR" --recursive >"$list_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -F "$TOP_FILE" "$list_log" >/dev/null 2>&1 && \
   grep -F "$NESTED_FILE" "$list_log" >/dev/null 2>&1 && \
   grep -F "$SUID_FILE" "$list_log" >/dev/null 2>&1; then
    echo "[PASS] linux list-files enumerates nested files from a real directory tree"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files enumerates nested files from a real directory tree (rc=$rc)"
    print_file_head_scrubbed "$list_log" 120
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$list_log"

suid_log="$(mktemp /tmp/ela_list_files_suid.XXXXXX)"
TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" linux list-files "$TMP_DIR" --recursive --suid-only >"$suid_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -F "$SUID_FILE" "$suid_log" >/dev/null 2>&1 && \
   ! grep -F "$TOP_FILE" "$suid_log" >/dev/null 2>&1; then
    echo "[PASS] linux list-files --suid-only filters to SUID entries"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files --suid-only filters to SUID entries (rc=$rc)"
    print_file_head_scrubbed "$suid_log" 120
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$suid_log"

symlink_log="$(mktemp /tmp/ela_list_symlinks_integration.XXXXXX)"
TEST_DISABLE_OUTPUT_OVERRIDE=1 ELA_OUTPUT_FORMAT=json run_with_output_override \
    "$BIN" linux list-symlinks "$TMP_DIR" --recursive >"$symlink_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -F "\"path\":\"$SYMLINK_FILE\"" "$symlink_log" >/dev/null 2>&1 && \
   grep -F "\"target\":\"$TOP_FILE\"" "$symlink_log" >/dev/null 2>&1; then
    echo "[PASS] linux list-symlinks emits real symlink records"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks emits real symlink records (rc=$rc)"
    print_file_head_scrubbed "$symlink_log" 120
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$symlink_log"

grep_log="$(mktemp /tmp/ela_grep_integration.XXXXXX)"
TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override \
    "$BIN" linux grep --search needle --path "$TMP_DIR" --recursive >"$grep_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -F "$TOP_FILE:1:needle top" "$grep_log" >/dev/null 2>&1 && \
   grep -F "$NESTED_FILE:1:nested needle line" "$grep_log" >/dev/null 2>&1 && \
   ! grep -F "$OTHER_FILE" "$grep_log" >/dev/null 2>&1; then
    echo "[PASS] linux grep finds recursive matches from real files"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux grep finds recursive matches from real files (rc=$rc)"
    print_file_head_scrubbed "$grep_log" 120
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$grep_log"

exec_log="$(mktemp /tmp/ela_execute_command_integration.XXXXXX)"
TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override \
    "$BIN" linux execute-command "printf integration-exec-output" >"$exec_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -F "integration-exec-output" "$exec_log" >/dev/null 2>&1; then
    echo "[PASS] linux execute-command runs a real shell command and relays stdout"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux execute-command runs a real shell command and relays stdout (rc=$rc)"
    print_file_head_scrubbed "$exec_log" 120
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$exec_log"

remote_req_path="$(mktemp /tmp/ela_remote_copy_path.XXXXXX)"
remote_req_type="$(mktemp /tmp/ela_remote_copy_type.XXXXXX)"
remote_req_body="$(mktemp /tmp/ela_remote_copy_body.XXXXXX)"
remote_server_log="$(mktemp /tmp/ela_remote_copy_server.XXXXXX)"
remote_cmd_log="$(mktemp /tmp/ela_remote_copy_cmd.XXXXXX)"

remote_server_pid="$(start_http_capture_server "$remote_server_log" "$remote_req_path" "$remote_req_type" "$remote_req_body" 200 || true)"
remote_port="$(wait_for_http_capture_server_ready "$remote_server_log" || true)"
if [ -n "$remote_server_pid" ] && [ -n "$remote_port" ]; then
    TEST_DISABLE_OUTPUT_OVERRIDE=1 "$BIN" --output-http "http://127.0.0.1:$remote_port" \
        linux remote-copy "$TOP_FILE" >"$remote_cmd_log" 2>&1
    rc=$?
    wait "$remote_server_pid" 2>/dev/null || true

    if [ "$rc" -eq 0 ] && \
       grep -F "/upload/file?filePath=%2F" "$remote_req_path" >/dev/null 2>&1 && \
       grep -F "application/octet-stream" "$remote_req_type" >/dev/null 2>&1 && \
       cmp -s "$TOP_FILE" "$remote_req_body" && \
       grep -F "remote-copy copied path $TOP_FILE (1 file copied)" "$remote_cmd_log" >/dev/null 2>&1; then
        echo "[PASS] linux remote-copy uploads a real file to a loopback HTTP endpoint"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] linux remote-copy uploads a real file to a loopback HTTP endpoint (rc=$rc)"
        echo "--- command log ---"
        print_file_head_scrubbed "$remote_cmd_log" 120
        echo "--- request path ---"
        print_file_head_scrubbed "$remote_req_path" 20
        echo "--- request content-type ---"
        print_file_head_scrubbed "$remote_req_type" 20
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
else
    echo "[FAIL] linux remote-copy uploads a real file to a loopback HTTP endpoint (server did not start)"
    print_file_head_scrubbed "$remote_server_log" 80
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    if [ -n "$remote_server_pid" ]; then
        stop_background_server "$remote_server_pid"
    fi
fi

rm -f "$remote_req_path" "$remote_req_type" "$remote_req_body" "$remote_server_log" "$remote_cmd_log"
finish_tests
