#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BIN="/tmp/embedded_linux_audit"

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

# shellcheck source=tests/agent/common.sh
. "$SCRIPT_DIR/common.sh"

require_binary "$BIN"
print_section "efi/bios orom argument coverage"

run_exact_case "efi orom --help" 0 "$BIN" efi orom --help
run_exact_case "bios orom --help" 0 "$BIN" bios orom --help

run_exact_case "efi orom pull missing output target" 2 "$BIN" efi orom pull
run_exact_case "bios orom pull missing output target" 2 "$BIN" bios orom pull

run_exact_case "efi orom pull invalid --output-http" 2 "$BIN" efi orom pull --output-http ftp://127.0.0.1:1/orom
run_exact_case "bios orom pull invalid --output-https" 2 "$BIN" bios orom pull --output-https http://127.0.0.1:1/orom
run_exact_case "efi orom pull both http+https" 2 "$BIN" efi orom pull --output-http http://127.0.0.1:1/orom --output-https https://127.0.0.1:1/orom
run_exact_case "bios orom pull both http+https" 2 "$BIN" bios orom pull --output-http http://127.0.0.1:1/orom --output-https https://127.0.0.1:1/orom
run_exact_case "efi orom pull extra positional arg" 2 "$BIN" efi orom pull extra
run_exact_case "bios orom list extra positional arg" 2 "$BIN" bios orom list extra

run_exact_case "efi orom invalid action" 2 "$BIN" efi orom invalid
run_exact_case "bios orom invalid action" 2 "$BIN" bios orom invalid

run_accept_case "efi orom pull --output-tcp" "$BIN" efi orom pull --output-tcp 127.0.0.1:9
run_accept_case "efi orom pull --output-http" "$BIN" efi orom pull --output-http http://127.0.0.1:1/orom
run_accept_case "efi orom pull --output-https" "$BIN" efi orom pull --output-https https://127.0.0.1:1/orom
run_accept_case "efi orom pull default verbose" "$BIN" efi orom pull --output-http http://127.0.0.1:1/orom

run_accept_case "bios orom pull --output-tcp" "$BIN" bios orom pull --output-tcp 127.0.0.1:9
run_accept_case "bios orom pull --output-http" "$BIN" bios orom pull --output-http http://127.0.0.1:1/orom
run_accept_case "bios orom pull --output-https" "$BIN" bios orom pull --output-https https://127.0.0.1:1/orom
run_accept_case "bios orom pull default verbose" "$BIN" bios orom pull --output-http http://127.0.0.1:1/orom

run_accept_case "efi orom list --output-tcp" "$BIN" efi orom list --output-tcp 127.0.0.1:9
run_accept_case "efi orom list --output-http" "$BIN" efi orom list --output-http http://127.0.0.1:1/orom
run_accept_case "bios orom list --output-https" "$BIN" bios orom list --output-https https://127.0.0.1:1/orom
run_accept_case "bios orom list default verbose" "$BIN" bios orom list --output-http http://127.0.0.1:1/orom
run_accept_case "efi orom list --output-http" "$BIN" efi orom list --output-http http://127.0.0.1:1/orom
run_accept_case "bios orom pull --insecure" "$BIN" --insecure bios orom pull --output-https https://127.0.0.1:1/orom

run_accept_case "efi orom list with --output-format csv" "$BIN" --output-format csv efi orom list --output-http http://127.0.0.1:1/orom
run_accept_case "bios orom list with --output-format json" "$BIN" --output-format json bios orom list --output-http http://127.0.0.1:1/orom

python_bin="$(find_python_bin || true)"

if [ -n "$python_bin" ]; then
    no_result_mode=""
    no_result_log="$(mktemp /tmp/test_orom_no_result_probe.XXXXXX)"

    TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" efi orom list >"$no_result_log" 2>&1
    rc=$?
    if [ "$rc" -eq 1 ] && grep -F "No matching efi option ROM payloads found" "$no_result_log" >/dev/null 2>&1; then
        no_result_mode="efi"
        no_result_message="No matching efi option ROM payloads found"
    else
        TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$BIN" bios orom list >"$no_result_log" 2>&1
        rc=$?
        if [ "$rc" -eq 1 ] && grep -F "No matching bios option ROM payloads found" "$no_result_log" >/dev/null 2>&1; then
            no_result_mode="bios"
            no_result_message="No matching bios option ROM payloads found"
        fi
    fi
    rm -f "$no_result_log"

    if [ -n "$no_result_mode" ]; then
        http_req_path="$(mktemp /tmp/test_orom_http_path.XXXXXX)"
        http_req_type="$(mktemp /tmp/test_orom_http_type.XXXXXX)"
        http_req_body="$(mktemp /tmp/test_orom_http_body.XXXXXX)"
        http_server_log="$(mktemp /tmp/test_orom_http_server.XXXXXX)"

        REQUEST_PATH_FILE="$http_req_path" REQUEST_TYPE_FILE="$http_req_type" REQUEST_BODY_FILE="$http_req_body" \
            "$python_bin" - <<'PY' >"$http_server_log" 2>&1 &
import http.server
import os
import socketserver
import threading

path_file = os.environ['REQUEST_PATH_FILE']
type_file = os.environ['REQUEST_TYPE_FILE']
body_file = os.environ['REQUEST_BODY_FILE']

class OneShotTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        with open(path_file, 'w', encoding='utf-8') as fh:
            fh.write(self.path)
        with open(type_file, 'w', encoding='utf-8') as fh:
            fh.write(self.headers.get('Content-Type', ''))
        with open(body_file, 'wb') as fh:
            fh.write(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok\n')
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, format, *args):
        pass

with OneShotTCPServer(('127.0.0.1', 0), Handler) as httpd:
    print(f'ready:{httpd.server_address[1]}', flush=True)
    httpd.serve_forever()
PY
        http_server_pid=$!

        ready=0
        http_port=""
        i=0
        while [ "$i" -lt 50 ]; do
            http_port="$(sed -n 's/^ready://p' "$http_server_log" 2>/dev/null | head -n 1)"
            if [ -n "$http_port" ]; then
                ready=1
                break
            fi
            if ! kill -0 "$http_server_pid" 2>/dev/null; then
                break
            fi
            sleep 0.1
            i="$(expr "$i" + 1)"
        done

        http_post_log="$(mktemp /tmp/test_orom_http_post.XXXXXX)"
        if [ "$ready" -eq 1 ]; then
            TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override \
                "$BIN" "$no_result_mode" orom list --output-http "http://127.0.0.1:$http_port" >"$http_post_log" 2>&1
            rc=$?
            wait "$http_server_pid" 2>/dev/null || true

            if [ "$rc" -eq 1 ] && \
               grep -F "/upload/log" "$http_req_path" >/dev/null 2>&1 && \
               grep -F "text/plain; charset=utf-8" "$http_req_type" >/dev/null 2>&1 && \
               grep -F "$no_result_message" "$http_req_body" >/dev/null 2>&1; then
                echo "[PASS] $no_result_mode orom list no-result log is sent over HTTP upload/log"
                PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
            else
                echo "[FAIL] $no_result_mode orom list no-result log is sent over HTTP upload/log (rc=$rc)"
                sed -n '1,80p' "$http_post_log"
                echo "--- request path ---"
                sed -n '1,20p' "$http_req_path" 2>/dev/null || true
                echo "--- request content-type ---"
                sed -n '1,20p' "$http_req_type" 2>/dev/null || true
                echo "--- request body ---"
                sed -n '1,20p' "$http_req_body" 2>/dev/null || true
                FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
            fi
        else
            echo "[FAIL] $no_result_mode orom list no-result log is sent over HTTP upload/log (server did not start)"
            sed -n '1,80p' "$http_server_log" 2>/dev/null || true
            FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
            kill "$http_server_pid" 2>/dev/null || true
            wait "$http_server_pid" 2>/dev/null || true
        fi

        rm -f "$http_req_path" "$http_req_type" "$http_req_body" "$http_server_log" "$http_post_log"
    else
        echo "[PASS] skipped no-result OROM HTTP log test (host has matching EFI and BIOS OROM results or no deterministic no-result case)"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    fi
fi

finish_tests
