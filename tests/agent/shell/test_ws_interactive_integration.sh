#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$SCRIPT_DIR"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "websocket interactive integration coverage"

NODE_BIN="$(find_node_bin || true)"
WS_SERVER_JS="$SHELL_TEST_ROOT/ws_capture_server.js"
WS_MODULE_DIR="$REPO_ROOT/api/terminal/node_modules/ws"

if [ -z "$NODE_BIN" ] || [ ! -f "$WS_SERVER_JS" ] || [ ! -d "$WS_MODULE_DIR" ]; then
    echo "[SKIP] websocket integration requires node and api/terminal/node_modules/ws"
    finish_tests
fi

run_ws_case() {
    name="$1"
    command_string="$2"
    expected_start="$3"
    expected_output="$4"

    ws_events="$(mktemp /tmp/ela_ws_events.XXXXXX)"
    ws_messages="$(mktemp /tmp/ela_ws_messages.XXXXXX)"
    ws_server_log="$(mktemp /tmp/ela_ws_server.XXXXXX)"
    cmd_log="$(mktemp /tmp/ela_ws_cmd.XXXXXX)"

    WS_MODULE_DIR="$WS_MODULE_DIR" "$NODE_BIN" "$WS_SERVER_JS" \
        --events-out "$ws_events" \
        --messages-out "$ws_messages" \
        --command-text "linux execute-command \"printf $expected_output\"" \
        --expect-text "$expected_output" >"$ws_server_log" 2>&1 &
    server_pid=$!

    ws_port="$(wait_for_http_capture_server_ready "$ws_server_log" || true)"
    if [ -z "$ws_port" ]; then
        echo "[FAIL] $name (server did not start)"
        print_file_head_scrubbed "$ws_server_log" 80
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        stop_background_server "$server_pid"
        rm -f "$ws_events" "$ws_messages" "$ws_server_log" "$cmd_log"
        return 1
    fi

    sh -c "$(printf '%s' "$command_string" | sed "s/__WS_PORT__/$ws_port/g")" >"$cmd_log" 2>&1
    rc=$?
    session_pid="$(sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' "$cmd_log" | tail -n 1)"

    if ! wait_for_background_process_exit "$server_pid" 80; then
        echo "[FAIL] $name (server did not finish)"
        print_file_head_scrubbed "$ws_server_log" 80
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
        stop_background_server "$server_pid"
        if [ -n "$session_pid" ]; then
            kill "$session_pid" 2>/dev/null || true
            wait "$session_pid" 2>/dev/null || true
        fi
        rm -f "$ws_events" "$ws_messages" "$ws_server_log" "$cmd_log"
        return 1
    fi

    if [ -n "$session_pid" ] && kill -0 "$session_pid" 2>/dev/null; then
        session_alive=1
        kill "$session_pid" 2>/dev/null || true
        wait "$session_pid" 2>/dev/null || true
    else
        session_alive=0
    fi

    if [ "$rc" -eq 0 ] && \
       grep -F "$expected_start" "$cmd_log" >/dev/null 2>&1 && \
       grep -F "connection:/terminal/" "$ws_events" >/dev/null 2>&1 && \
       grep -F "ping_sent" "$ws_events" >/dev/null 2>&1 && \
       grep -F "pong" "$ws_events" >/dev/null 2>&1 && \
       grep -F "heartbeat_ack" "$ws_events" >/dev/null 2>&1 && \
       grep -F "command_sent" "$ws_events" >/dev/null 2>&1 && \
       grep -F "expected_output_seen" "$ws_events" >/dev/null 2>&1 && \
       grep -F "$expected_output" "$ws_messages" >/dev/null 2>&1 && \
       [ "$session_alive" -eq 0 ]; then
        echo "[PASS] $name"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] $name (rc=$rc, session_alive=$session_alive)"
        echo "--- command log ---"
        print_file_head_scrubbed "$cmd_log" 120
        echo "--- ws events ---"
        print_file_head_scrubbed "$ws_events" 120
        echo "--- ws messages ---"
        print_file_head_scrubbed "$ws_messages" 120
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi

    rm -f "$ws_events" "$ws_messages" "$ws_server_log" "$cmd_log"
    return 0
}

run_ws_case \
    "--remote ws:// relays commands, output, ping/pong, and heartbeat ack" \
    "\"$BIN\" --remote \"ws://127.0.0.1:__WS_PORT__\"" \
    "Remote session started" \
    "ws-remote-output"

run_ws_case \
    "transfer ws:// relays commands, output, ping/pong, and heartbeat ack" \
    "\"$BIN\" transfer \"ws://127.0.0.1:__WS_PORT__\"" \
    "Transfer started" \
    "ws-transfer-output"

finish_tests
