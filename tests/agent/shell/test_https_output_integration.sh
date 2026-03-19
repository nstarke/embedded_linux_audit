#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$SCRIPT_DIR"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "https output integration coverage"

CERT_PATH="$REPO_ROOT/tools/certs/localhost.crt"
KEY_PATH="$REPO_ROOT/tools/certs/localhost.key"

if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "[SKIP] https integration requires tools/certs/localhost.crt and localhost.key"
    finish_tests
fi

run_https_capture_case() {
    name="$1"
    mode="$2"
    command_template="$3"
    payload_path="${4:-}"

    req_path="$(mktemp /tmp/ela_https_req_path.XXXXXX)"
    req_type="$(mktemp /tmp/ela_https_req_type.XXXXXX)"
    req_body="$(mktemp /tmp/ela_https_req_body.XXXXXX)"
    server_log="$(mktemp /tmp/ela_https_server.XXXXXX)"
    cmd_log="$(mktemp /tmp/ela_https_cmd.XXXXXX)"

    server_pid="$(start_https_capture_server "$server_log" "$mode" "$CERT_PATH" "$KEY_PATH" "$req_path" "$req_type" "$req_body" "$payload_path" || true)"
    if [ -z "$server_pid" ]; then
        echo "[FAIL] $name (unable to start local HTTPS capture server)"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        rm -f "$req_path" "$req_type" "$req_body" "$server_log" "$cmd_log"
        return 1
    fi

    https_port="$(wait_for_http_capture_server_ready "$server_log" || true)"
    if [ -z "$https_port" ]; then
        echo "[FAIL] $name (server did not start)"
        print_file_head_scrubbed "$server_log" 80
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        stop_background_server "$server_pid"
        rm -f "$req_path" "$req_type" "$req_body" "$server_log" "$cmd_log"
        return 1
    fi

    command_string="$(printf '%s' "$command_template" | sed "s/__HTTPS_PORT__/$https_port/g")"
    TEST_DISABLE_OUTPUT_OVERRIDE=1 sh -c "$command_string" >"$cmd_log" 2>&1
    rc=$?

    if kill -0 "$server_pid" 2>/dev/null; then
        stop_background_server "$server_pid"
    else
        wait "$server_pid" 2>/dev/null || true
    fi

    HTTPS_CASE_RC="$rc"
    HTTPS_CASE_REQ_PATH="$req_path"
    HTTPS_CASE_REQ_TYPE="$req_type"
    HTTPS_CASE_REQ_BODY="$req_body"
    HTTPS_CASE_SERVER_LOG="$server_log"
    HTTPS_CASE_CMD_LOG="$cmd_log"
    return 0
}

cleanup_https_capture_case() {
    rm -f "$HTTPS_CASE_REQ_PATH" "$HTTPS_CASE_REQ_TYPE" "$HTTPS_CASE_REQ_BODY" \
        "$HTTPS_CASE_SERVER_LOG" "$HTTPS_CASE_CMD_LOG"
}

run_https_capture_case "arch isa rejects self-signed HTTPS upload without --insecure" post \
    "\"$BIN\" --quiet --output-format json --output-http \"https://127.0.0.1:__HTTPS_PORT__\" arch isa"
if [ "$HTTPS_CASE_RC" -ne 0 ] && \
   [ ! -s "$HTTPS_CASE_REQ_PATH" ] && \
   grep -E "HTTP POST failed|SSL|certificate|self signed" "$HTTPS_CASE_CMD_LOG" >/dev/null 2>&1; then
    echo "[PASS] arch isa rejects self-signed HTTPS upload without --insecure"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] arch isa rejects self-signed HTTPS upload without --insecure (rc=$HTTPS_CASE_RC)"
    print_file_head_scrubbed "$HTTPS_CASE_CMD_LOG" 120
    echo "--- request path ---"
    print_file_head_scrubbed "$HTTPS_CASE_REQ_PATH" 20
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
cleanup_https_capture_case

run_https_capture_case "arch isa accepts self-signed HTTPS upload with --insecure" post \
    "\"$BIN\" --insecure --quiet --output-format json --output-http \"https://127.0.0.1:__HTTPS_PORT__\" arch isa"
if [ "$HTTPS_CASE_RC" -eq 0 ] && \
   grep -F "/upload/arch" "$HTTPS_CASE_REQ_PATH" >/dev/null 2>&1 && \
   grep -F "application/json; charset=utf-8" "$HTTPS_CASE_REQ_TYPE" >/dev/null 2>&1 && \
   grep -F '"record":"arch"' "$HTTPS_CASE_REQ_BODY" >/dev/null 2>&1; then
    echo "[PASS] arch isa accepts self-signed HTTPS upload with --insecure"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] arch isa accepts self-signed HTTPS upload with --insecure (rc=$HTTPS_CASE_RC)"
    print_file_head_scrubbed "$HTTPS_CASE_CMD_LOG" 120
    echo "--- request path ---"
    print_file_head_scrubbed "$HTTPS_CASE_REQ_PATH" 20
    echo "--- request body ---"
    print_file_head_scrubbed "$HTTPS_CASE_REQ_BODY" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
cleanup_https_capture_case

DOWNLOAD_SRC="$(mktemp /tmp/ela_https_download_src.XXXXXX)"
DOWNLOAD_DST="$(mktemp /tmp/ela_https_download_dst.XXXXXX)"
rm -f "$DOWNLOAD_DST"
printf 'https-download-payload' >"$DOWNLOAD_SRC"

run_https_capture_case "linux download-file rejects self-signed HTTPS without --insecure" file \
    "\"$BIN\" linux download-file \"https://127.0.0.1:__HTTPS_PORT__/file.bin\" \"$DOWNLOAD_DST\"" \
    "$DOWNLOAD_SRC"
if [ "$HTTPS_CASE_RC" -ne 0 ] && \
   [ ! -s "$DOWNLOAD_DST" ] && \
   grep -F "download-file downloaded 0 bytes success=false" "$HTTPS_CASE_CMD_LOG" >/dev/null 2>&1; then
    echo "[PASS] linux download-file rejects self-signed HTTPS without --insecure"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux download-file rejects self-signed HTTPS without --insecure (rc=$HTTPS_CASE_RC)"
    print_file_head_scrubbed "$HTTPS_CASE_CMD_LOG" 120
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
cleanup_https_capture_case
rm -f "$DOWNLOAD_DST"

run_https_capture_case "linux download-file accepts self-signed HTTPS with --insecure" file \
    "\"$BIN\" --insecure linux download-file \"https://127.0.0.1:__HTTPS_PORT__/file.bin\" \"$DOWNLOAD_DST\"" \
    "$DOWNLOAD_SRC"
if [ "$HTTPS_CASE_RC" -eq 0 ] && \
   cmp -s "$DOWNLOAD_SRC" "$DOWNLOAD_DST" && \
   grep -F "/file.bin" "$HTTPS_CASE_REQ_PATH" >/dev/null 2>&1 && \
   grep -F "download-file downloaded 22 bytes success=true" "$HTTPS_CASE_CMD_LOG" >/dev/null 2>&1; then
    echo "[PASS] linux download-file accepts self-signed HTTPS with --insecure"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux download-file accepts self-signed HTTPS with --insecure (rc=$HTTPS_CASE_RC)"
    print_file_head_scrubbed "$HTTPS_CASE_CMD_LOG" 120
    echo "--- request path ---"
    print_file_head_scrubbed "$HTTPS_CASE_REQ_PATH" 20
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
cleanup_https_capture_case

rm -f "$DOWNLOAD_SRC" "$DOWNLOAD_DST"
finish_tests
