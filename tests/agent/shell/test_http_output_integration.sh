#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$SCRIPT_DIR"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
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
print_section "http output integration coverage"

run_http_capture_case() {
    name="$1"
    status_code="$2"
    command_template="$3"

    req_path="$(mktemp /tmp/ela_http_req_path.XXXXXX)"
    req_type="$(mktemp /tmp/ela_http_req_type.XXXXXX)"
    req_body="$(mktemp /tmp/ela_http_req_body.XXXXXX)"
    server_log="$(mktemp /tmp/ela_http_server.XXXXXX)"
    cmd_log="$(mktemp /tmp/ela_http_cmd.XXXXXX)"

    server_pid="$(start_http_capture_server "$server_log" "$req_path" "$req_type" "$req_body" "$status_code" || true)"
    if [ -z "$server_pid" ]; then
        echo "[FAIL] $name (unable to start local HTTP capture server)"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        rm -f "$req_path" "$req_type" "$req_body" "$server_log" "$cmd_log"
        return
    fi

    http_port="$(wait_for_http_capture_server_ready "$server_log" || true)"
    if [ -z "$http_port" ]; then
        echo "[FAIL] $name (server did not start)"
        print_file_head_scrubbed "$server_log" 80
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        stop_background_server "$server_pid"
        rm -f "$req_path" "$req_type" "$req_body" "$server_log" "$cmd_log"
        return
    fi

    command_string="$(printf '%s' "$command_template" | sed "s/__HTTP_PORT__/$http_port/g")"
    TEST_DISABLE_OUTPUT_OVERRIDE=1 sh -c "$command_string" >"$cmd_log" 2>&1
    rc=$?
    wait "$server_pid" 2>/dev/null || true

    HTTP_CASE_RC="$rc"
    HTTP_CASE_REQ_PATH="$req_path"
    HTTP_CASE_REQ_TYPE="$req_type"
    HTTP_CASE_REQ_BODY="$req_body"
    HTTP_CASE_SERVER_LOG="$server_log"
    HTTP_CASE_CMD_LOG="$cmd_log"
}

cleanup_http_capture_case() {
    rm -f "$HTTP_CASE_REQ_PATH" "$HTTP_CASE_REQ_TYPE" "$HTTP_CASE_REQ_BODY" \
        "$HTTP_CASE_SERVER_LOG" "$HTTP_CASE_CMD_LOG"
}

TMP_DIR="$(mktemp -d /tmp/ela_http_output.XXXXXX)"
TMP_FILE_TOP="$TMP_DIR/top.txt"
TMP_NESTED_DIR="$TMP_DIR/nested"
TMP_FILE_NESTED="$TMP_NESTED_DIR/nested.txt"
TMP_LINK="$TMP_DIR/link-top"
mkdir -p "$TMP_NESTED_DIR"
echo "needle on top" >"$TMP_FILE_TOP"
echo "needle in nested" >"$TMP_FILE_NESTED"
ln -sf /tmp/http-output-target "$TMP_LINK"

run_http_capture_case "arch isa posts json record over HTTP" 200 \
    "\"$BIN\" --quiet --output-format json --output-http \"http://127.0.0.1:__HTTP_PORT__\" arch isa"
if [ "$HTTP_CASE_RC" -eq 0 ] && \
   grep -F "/upload/arch" "$HTTP_CASE_REQ_PATH" >/dev/null 2>&1 && \
   grep -F "application/json; charset=utf-8" "$HTTP_CASE_REQ_TYPE" >/dev/null 2>&1 && \
   grep -F '"record":"arch"' "$HTTP_CASE_REQ_BODY" >/dev/null 2>&1 && \
   grep -F '"subcommand":"isa"' "$HTTP_CASE_REQ_BODY" >/dev/null 2>&1; then
    echo "[PASS] arch isa posts json record over HTTP"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] arch isa posts json record over HTTP (rc=$HTTP_CASE_RC)"
    print_file_head_scrubbed "$HTTP_CASE_CMD_LOG" 80
    echo "--- request path ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_PATH" 20
    echo "--- request content-type ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_TYPE" 20
    echo "--- request body ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_BODY" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
cleanup_http_capture_case

run_http_capture_case "arch isa surfaces HTTP 500 upload failures" 500 \
    "\"$BIN\" --quiet --output-format json --output-http \"http://127.0.0.1:__HTTP_PORT__\" arch isa"
if [ "$HTTP_CASE_RC" -eq 1 ] && \
   grep -F "/upload/arch" "$HTTP_CASE_REQ_PATH" >/dev/null 2>&1 && \
   grep -F "arch: HTTP POST failed" "$HTTP_CASE_CMD_LOG" >/dev/null 2>&1; then
    echo "[PASS] arch isa surfaces HTTP 500 upload failures"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] arch isa surfaces HTTP 500 upload failures (rc=$HTTP_CASE_RC)"
    print_file_head_scrubbed "$HTTP_CASE_CMD_LOG" 80
    echo "--- request path ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_PATH" 20
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
cleanup_http_capture_case

dmesg_supported=1
run_http_capture_case "linux dmesg posts text output over HTTP" 200 \
    "\"$BIN\" --quiet --output-http \"http://127.0.0.1:__HTTP_PORT__\" linux dmesg"
if [ "$HTTP_CASE_RC" -eq 0 ] && \
   grep -F "/upload/dmesg" "$HTTP_CASE_REQ_PATH" >/dev/null 2>&1 && \
   grep -F "text/plain; charset=utf-8" "$HTTP_CASE_REQ_TYPE" >/dev/null 2>&1 && \
   [ -s "$HTTP_CASE_REQ_BODY" ]; then
    echo "[PASS] linux dmesg posts text output over HTTP"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
elif grep -E "Operation not permitted|Permission denied|dmesg: read kernel buffer failed" "$HTTP_CASE_CMD_LOG" >/dev/null 2>&1; then
    echo "[SKIP] linux dmesg posts text output over HTTP (kernel log access is restricted)"
else
    echo "[FAIL] linux dmesg posts text output over HTTP (rc=$HTTP_CASE_RC)"
    print_file_head_scrubbed "$HTTP_CASE_CMD_LOG" 80
    echo "--- request path ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_PATH" 20
    echo "--- request body ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_BODY" 20
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
cleanup_http_capture_case

run_http_capture_case "linux grep posts grep matches over HTTP" 200 \
    "\"$BIN\" --quiet --output-http \"http://127.0.0.1:__HTTP_PORT__\" linux grep --search needle --path \"$TMP_DIR\" --recursive"
if [ "$HTTP_CASE_RC" -eq 0 ] && \
   grep -F "/upload/grep?filePath=" "$HTTP_CASE_REQ_PATH" >/dev/null 2>&1 && \
   grep -F "text/plain; charset=utf-8" "$HTTP_CASE_REQ_TYPE" >/dev/null 2>&1 && \
   grep -F "$TMP_FILE_TOP" "$HTTP_CASE_REQ_BODY" >/dev/null 2>&1 && \
   grep -F "needle" "$HTTP_CASE_REQ_BODY" >/dev/null 2>&1; then
    echo "[PASS] linux grep posts grep matches over HTTP"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux grep posts grep matches over HTTP (rc=$HTTP_CASE_RC)"
    print_file_head_scrubbed "$HTTP_CASE_CMD_LOG" 80
    echo "--- request path ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_PATH" 20
    echo "--- request body ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_BODY" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
cleanup_http_capture_case

run_http_capture_case "linux list-files posts recursive file listings over HTTP" 200 \
    "\"$BIN\" --quiet --output-http \"http://127.0.0.1:__HTTP_PORT__\" linux list-files \"$TMP_DIR\" --recursive"
if [ "$HTTP_CASE_RC" -eq 0 ] && \
   grep -F "/upload/file-list?filePath=%2F" "$HTTP_CASE_REQ_PATH" >/dev/null 2>&1 && \
   grep -F "text/plain; charset=utf-8" "$HTTP_CASE_REQ_TYPE" >/dev/null 2>&1 && \
   file_has_exact_line "$TMP_FILE_TOP" "$HTTP_CASE_REQ_BODY" && \
   file_has_exact_line "$TMP_FILE_NESTED" "$HTTP_CASE_REQ_BODY"; then
    echo "[PASS] linux list-files posts recursive file listings over HTTP"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-files posts recursive file listings over HTTP (rc=$HTTP_CASE_RC)"
    print_file_head_scrubbed "$HTTP_CASE_CMD_LOG" 80
    echo "--- request path ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_PATH" 20
    echo "--- request body ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_BODY" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
cleanup_http_capture_case

run_http_capture_case "linux list-symlinks posts symlink listings over HTTP" 200 \
    "\"$BIN\" --quiet --output-http \"http://127.0.0.1:__HTTP_PORT__\" linux list-symlinks \"$TMP_DIR\""
if [ "$HTTP_CASE_RC" -eq 0 ] && \
   grep -F "/upload/symlink-list?filePath=%2F" "$HTTP_CASE_REQ_PATH" >/dev/null 2>&1 && \
   grep -F "text/plain; charset=utf-8" "$HTTP_CASE_REQ_TYPE" >/dev/null 2>&1 && \
   file_has_exact_line "$TMP_LINK -> /tmp/http-output-target" "$HTTP_CASE_REQ_BODY"; then
    echo "[PASS] linux list-symlinks posts symlink listings over HTTP"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux list-symlinks posts symlink listings over HTTP (rc=$HTTP_CASE_RC)"
    print_file_head_scrubbed "$HTTP_CASE_CMD_LOG" 80
    echo "--- request path ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_PATH" 20
    echo "--- request body ---"
    print_file_head_scrubbed "$HTTP_CASE_REQ_BODY" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
cleanup_http_capture_case

if [ "$(current_uid)" -eq 0 ]; then
    TMP_ENV_IMAGE="$(mktemp /tmp/uboot_env_http.XXXXXX.bin)"
    python_bin="$(find_python_bin || true)"
    if [ -n "$python_bin" ]; then
        "$python_bin" - "$TMP_ENV_IMAGE" <<'PY'
import binascii
import struct
import sys

path = sys.argv[1]
env_size = 0x10000
data = bytearray(b'\x00' * (env_size - 4))
payload = b'bootcmd=run distro_bootcmd\x00baudrate=115200\x00\x00'
data[:len(payload)] = payload
crc = binascii.crc32(data) & 0xFFFFFFFF
image = struct.pack('<I', crc) + data

with open(path, 'wb') as f:
    f.write(image)
PY

        run_http_capture_case "uboot env read-vars posts NDJSON environment records over HTTP" 200 \
            "\"$BIN\" --quiet --output-format json --output-http \"http://127.0.0.1:__HTTP_PORT__\" uboot env read-vars --size \"$TEST_SIZE\" \"$TMP_ENV_IMAGE:0x10000\""
        if [ "$HTTP_CASE_RC" -eq 0 ] && \
           grep -F "/upload/uboot-environment" "$HTTP_CASE_REQ_PATH" >/dev/null 2>&1 && \
           grep -F "application/x-ndjson; charset=utf-8" "$HTTP_CASE_REQ_TYPE" >/dev/null 2>&1 && \
           grep -F '"key":"bootcmd"' "$HTTP_CASE_REQ_BODY" >/dev/null 2>&1 && \
           grep -F '"value":"run distro_bootcmd"' "$HTTP_CASE_REQ_BODY" >/dev/null 2>&1; then
            echo "[PASS] uboot env read-vars posts NDJSON environment records over HTTP"
            PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
        else
            echo "[FAIL] uboot env read-vars posts NDJSON environment records over HTTP (rc=$HTTP_CASE_RC)"
            print_file_head_scrubbed "$HTTP_CASE_CMD_LOG" 80
            echo "--- request path ---"
            print_file_head_scrubbed "$HTTP_CASE_REQ_PATH" 20
            echo "--- request body ---"
            print_file_head_scrubbed "$HTTP_CASE_REQ_BODY" 40
            FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        fi
        cleanup_http_capture_case
    else
        echo "[SKIP] uboot env read-vars HTTP integration requires python3 or python"
    fi
    rm -f "$TMP_ENV_IMAGE"
else
    echo "[SKIP] uboot env read-vars HTTP integration requires root"
fi

rm -rf "$TMP_DIR"
finish_tests
