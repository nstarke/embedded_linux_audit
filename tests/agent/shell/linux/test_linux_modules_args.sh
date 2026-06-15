#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux modules subcommand argument coverage"

fake_module="$(mktemp /tmp/ela-fake-module.XXXXXX.ko)"
printf 'not an elf\0license=GPL\0vermagic=6.1.0-test SMP preempt mod_unload x86_64\0name=demo\0' >"$fake_module"
trap 'rm -f "$fake_module"' EXIT INT TERM

run_exact_case "linux modules --help" 0 "$BIN" linux modules --help
run_exact_case "linux modules list --help" 0 "$BIN" linux modules list --help
run_exact_case "linux modules vermagic --help" 0 "$BIN" linux modules vermagic --help
run_accept_case "linux modules list" "$BIN" linux modules list
run_accept_case "linux modules list json" "$BIN" --output-format json linux modules list
run_accept_case "linux modules list csv" "$BIN" --output-format csv linux modules list
run_exact_case "linux modules vermagic" 0 "$BIN" linux modules vermagic "$fake_module"
run_exact_case "linux modules vermagic json" 0 "$BIN" --output-format json linux modules vermagic "$fake_module"
run_exact_case "linux modules vermagic csv" 0 "$BIN" --output-format csv linux modules vermagic "$fake_module"
run_exact_case "linux modules no action" 0 "$BIN" linux modules
run_exact_case "linux modules unknown action" 2 "$BIN" linux modules reload demo
run_exact_case "linux modules list extra arg" 2 "$BIN" linux modules list extra
run_exact_case "linux modules load missing path" 2 "$BIN" linux modules load
run_exact_case "linux modules load missing file" 1 "$BIN" linux modules load /tmp/definitely-missing-ela-module.ko
run_exact_case "linux modules load --force missing file" 1 "$BIN" linux modules load --force /tmp/definitely-missing-ela-module.ko
run_exact_case "linux modules unload missing name" 2 "$BIN" linux modules unload
run_exact_case "linux modules unload extra arg" 2 "$BIN" linux modules unload demo extra
run_exact_case "linux modules vermagic missing path" 2 "$BIN" linux modules vermagic
run_exact_case "linux modules vermagic extra arg" 2 "$BIN" linux modules vermagic "$fake_module" extra
run_exact_case "linux modules vermagic missing file" 1 "$BIN" linux modules vermagic /tmp/definitely-missing-ela-module.ko

vermagic_log="$(mktemp /tmp/test_linux_modules_vermagic.XXXXXX)"
"$BIN" --output-format json linux modules vermagic "$fake_module" >"$vermagic_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -q '"vermagic":"6.1.0-test SMP preempt mod_unload x86_64"' "$vermagic_log"; then
    echo "[PASS] linux modules vermagic emits extracted vermagic"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux modules vermagic emits extracted vermagic (rc=$rc)"
    print_file_head_scrubbed "$vermagic_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$vermagic_log"

http_req_path="$(mktemp /tmp/test_modules_vermagic_http_path.XXXXXX)"
http_req_type="$(mktemp /tmp/test_modules_vermagic_http_type.XXXXXX)"
http_req_body="$(mktemp /tmp/test_modules_vermagic_http_body.XXXXXX)"
http_server_log="$(mktemp /tmp/test_modules_vermagic_http_server.XXXXXX)"
http_cmd_log="$(mktemp /tmp/test_modules_vermagic_http_cmd.XXXXXX)"
python_bin="$(find_python_bin || true)"
http_server_pid=""
http_port=""
if [ -n "$python_bin" ]; then
    "$python_bin" "$SCRIPT_DIR/http_capture_server.py" \
        --path-out "$http_req_path" \
        --type-out "$http_req_type" \
        --body-out "$http_req_body" \
        --status 200 >"$http_server_log" 2>&1 &
    http_server_pid=$!
    http_port="$(wait_for_http_capture_server_ready "$http_server_log" || true)"
fi
if [ -n "$http_port" ]; then
    TEST_DISABLE_OUTPUT_OVERRIDE=1 "$BIN" --output-format json \
        --output-http "http://127.0.0.1:$http_port" \
        linux modules vermagic "$fake_module" >"$http_cmd_log" 2>&1
    rc=$?
    wait "$http_server_pid" 2>/dev/null || true
    if [ "$rc" -eq 0 ] && \
       grep -F "/upload/module-vermagic" "$http_req_path" >/dev/null 2>&1 && \
       grep -F "application/json; charset=utf-8" "$http_req_type" >/dev/null 2>&1 && \
       grep -F '"vermagic":"6.1.0-test SMP preempt mod_unload x86_64"' "$http_req_body" >/dev/null 2>&1; then
        echo "[PASS] linux modules vermagic posts output over HTTP"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] linux modules vermagic posts output over HTTP (rc=$rc)"
        print_file_head_scrubbed "$http_cmd_log" 80
        echo "--- request path ---"
        print_file_head_scrubbed "$http_req_path" 20
        echo "--- request type ---"
        print_file_head_scrubbed "$http_req_type" 20
        echo "--- request body ---"
        print_file_head_scrubbed "$http_req_body" 40
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
else
    echo "[SKIP] linux modules vermagic posts output over HTTP (python HTTP capture unavailable)"
fi
if [ -n "$http_server_pid" ]; then
    stop_background_server "$http_server_pid"
fi
rm -f "$http_req_path" "$http_req_type" "$http_req_body" "$http_server_log" "$http_cmd_log"

if [ -n "$python_bin" ]; then
    tcp_body="$(mktemp /tmp/test_modules_vermagic_tcp_body.XXXXXX)"
    tcp_server_log="$(mktemp /tmp/test_modules_vermagic_tcp_server.XXXXXX)"
    TCP_BODY_FILE="$tcp_body" "$python_bin" -c '
import os
import socket

body_file = os.environ["TCP_BODY_FILE"]
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    print(f"ready:{s.getsockname()[1]}", flush=True)
    conn, _addr = s.accept()
    with conn:
        chunks = []
        while True:
            data = conn.recv(4096)
            if not data:
                break
            chunks.append(data)
    with open(body_file, "wb") as fh:
        fh.write(b"".join(chunks))
' >"$tcp_server_log" 2>&1 &
    tcp_server_pid=$!
    tcp_port=""
    i=0
    while [ "$i" -lt 50 ]; do
        tcp_port="$(sed -n 's/^ready://p' "$tcp_server_log" 2>/dev/null | head -n 1)"
        if [ -n "$tcp_port" ]; then
            break
        fi
        sleep 0.1
        i="$(expr "$i" + 1)"
    done

    tcp_cmd_log="$(mktemp /tmp/test_modules_vermagic_tcp_cmd.XXXXXX)"
    if [ -n "$tcp_port" ]; then
        TEST_DISABLE_OUTPUT_OVERRIDE=1 "$BIN" --output-format json \
            --output-tcp "127.0.0.1:$tcp_port" \
            linux modules vermagic "$fake_module" >"$tcp_cmd_log" 2>&1
        rc=$?
        wait "$tcp_server_pid" 2>/dev/null || true
        if [ "$rc" -eq 0 ] && \
           grep -F '"vermagic":"6.1.0-test SMP preempt mod_unload x86_64"' "$tcp_body" >/dev/null 2>&1; then
            echo "[PASS] linux modules vermagic sends output over TCP"
            PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
        else
            echo "[FAIL] linux modules vermagic sends output over TCP (rc=$rc)"
            print_file_head_scrubbed "$tcp_cmd_log" 80
            echo "--- tcp body ---"
            print_file_head_scrubbed "$tcp_body" 40
            FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        fi
    else
        echo "[SKIP] linux modules vermagic sends output over TCP (python TCP capture did not start)"
        stop_background_server "$tcp_server_pid"
    fi
    rm -f "$tcp_body" "$tcp_server_log" "$tcp_cmd_log"
else
    echo "[SKIP] linux modules vermagic sends output over TCP (python unavailable)"
fi

finish_tests
