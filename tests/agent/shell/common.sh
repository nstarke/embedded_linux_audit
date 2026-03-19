#!/bin/sh

set -u

SCRIPT_DIR="${SHELL_TEST_ROOT:-$(CDPATH= cd -- "$(dirname "$0")" && pwd)}"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# When running standalone (downloaded to a temp directory), common_redaction.sh
# is placed alongside this file by download_tests.sh.  Fall back to the repo
# path when running from a checkout.
# shellcheck source=tests/common_redaction.sh
if [ -f "$SCRIPT_DIR/common_redaction.sh" ]; then
    . "$SCRIPT_DIR/common_redaction.sh"
else
    . "$REPO_ROOT/tests/common_redaction.sh"
fi

PASS_COUNT=0
FAIL_COUNT=0

# Shared test size used by --size argument coverage tests.
TEST_SIZE=0x10000

has_printf() {
    command_exists printf
}

find_python_bin() {
    ela_ensure_command python3 >/dev/null 2>&1 || true

    if command_exists python3; then
        echo python3
        return 0
    fi

    if command_exists python; then
        echo python
        return 0
    fi

    return 1
}

start_http_capture_server() {
    server_log="$1"
    req_path_out="$2"
    req_type_out="$3"
    req_body_out="$4"
    status_code="${5:-200}"
    req_auth_out="${6:-}"

    python_bin="$(find_python_bin || true)"
    if [ -z "$python_bin" ]; then
        return 1
    fi

    cmd="$python_bin \"$SCRIPT_DIR/http_capture_server.py\" --path-out \"$req_path_out\" --type-out \"$req_type_out\" --body-out \"$req_body_out\" --status \"$status_code\""
    if [ -n "$req_auth_out" ]; then
        cmd="$cmd --auth-out \"$req_auth_out\""
    fi

    # shellcheck disable=SC2086
    sh -c "$cmd" >"$server_log" 2>&1 &
    echo $!
}

wait_for_http_capture_server_ready() {
    server_log="$1"
    attempts="${2:-50}"
    i=0
    while [ "$i" -lt "$attempts" ]; do
        port="$(sed -n 's/^ready://p' "$server_log" 2>/dev/null | head -n 1)"
        if [ -n "$port" ]; then
            echo "$port"
            return 0
        fi
        sleep 0.1
        i="$(expr "$i" + 1)"
    done
    return 1
}

stop_background_server() {
    _pid="$1"
    kill "$_pid" 2>/dev/null || true
    wait "$_pid" 2>/dev/null || true
}

start_https_capture_server() {
    server_log="$1"
    mode="$2"
    cert_path="$3"
    key_path="$4"
    req_path_out="$5"
    req_type_out="$6"
    req_body_out="$7"
    payload_path="${8:-}"

    python_bin="$(find_python_bin || true)"
    if [ -z "$python_bin" ]; then
        return 1
    fi

    cmd="$python_bin \"$SCRIPT_DIR/https_capture_server.py\" --mode \"$mode\" --cert \"$cert_path\" --key \"$key_path\" --path-out \"$req_path_out\" --type-out \"$req_type_out\" --body-out \"$req_body_out\""
    if [ -n "$payload_path" ]; then
        cmd="$cmd --payload \"$payload_path\""
    fi

    # shellcheck disable=SC2086
    sh -c "$cmd" >"$server_log" 2>&1 &
    echo $!
}

command_exists() {
    cmd_name="$1"

    if command -v "$cmd_name" >/dev/null 2>&1; then
        return 0
    fi

    if type "$cmd_name" >/dev/null 2>&1; then
        return 0
    fi

    if which "$cmd_name" >/dev/null 2>&1; then
        return 0
    fi

    for candidate in /bin/"$cmd_name" /usr/bin/"$cmd_name" /sbin/"$cmd_name" /usr/sbin/"$cmd_name"; do
        if [ -x "$candidate" ]; then
            return 0
        fi
    done

    return 1
}

current_uid() {
    if command_exists id; then
        id -u
        return $?
    fi

    if [ -r /proc/self/status ]; then
        awk '/^Uid:/ { print $2; exit }' /proc/self/status
        return $?
    fi

    echo 1
}

current_user_name() {
    if command_exists id; then
        id -un
        return $?
    fi

    if [ -n "${USER:-}" ]; then
        echo "$USER"
        return 0
    fi

    if [ -r /proc/self/status ] && [ -r /etc/passwd ]; then
        uid="$(awk '/^Uid:/ { print $2; exit }' /proc/self/status 2>/dev/null)"
        if [ -n "$uid" ]; then
            awk -F: -v uid="$uid" '$3 == uid { print $1; exit }' /etc/passwd
            return $?
        fi
    fi

    echo root
}

current_group_name() {
    if command_exists id; then
        id -gn
        return $?
    fi

    if [ -n "${GROUP:-}" ]; then
        echo "$GROUP"
        return 0
    fi

    if [ -r /proc/self/status ] && [ -r /etc/group ]; then
        gid="$(awk '/^Gid:/ { print $2; exit }' /proc/self/status 2>/dev/null)"
        if [ -n "$gid" ]; then
            awk -F: -v gid="$gid" '$3 == gid { print $1; exit }' /etc/group
            return $?
        fi
    fi

    echo root
}

file_has_exact_line() {
    needle="$1"
    file="$2"

    while IFS= read -r line || [ -n "$line" ]; do
        if [ "$line" = "$needle" ]; then
            return 0
        fi
    done <"$file"

    return 1
}

append_line() {
    line="$1"
    if has_printf; then
        printf '%s\n' "$line"
    else
        cat <<EOF_APPEND_LINE
$line
EOF_APPEND_LINE
    fi
}

print_file_head_scrubbed() {
    path="$1"
    lines="${2:-80}"

    if [ -f "$path" ]; then
        sed -n "1,${lines}p" "$path" 2>/dev/null | scrub_sensitive_stream
    fi
}

run_with_output_override() {
    if [ "${TEST_DISABLE_OUTPUT_OVERRIDE:-0}" = "1" ]; then
        "$@"
        return $?
    fi

    override_flag=""
    override_value=""

    if [ -n "${TEST_OUTPUT_HTTP:-}" ]; then
        override_flag="--output-http"
        override_value="$TEST_OUTPUT_HTTP"
    fi

    if [ -z "$override_flag" ]; then
        "$@"
        return $?
    fi

    original_args_file="$(mktemp /tmp/test_args.XXXXXX)"
    for arg in "$@"; do
        append_line "$arg" >>"$original_args_file"
    done

    replaced=0
    set --
    while IFS= read -r arg; do
        case "$arg" in
            --output-http|--output-http|--output-tcp)
                set -- "$@" "$override_flag" "$override_value"
                IFS= read -r next_arg || true
                replaced=1
                ;;
            --output-http=*|--output-http=*|--output-tcp=*)
                set -- "$@" "$override_flag" "$override_value"
                replaced=1
                ;;
            *)
                set -- "$@" "$arg"
                ;;
        esac
    done <"$original_args_file"

    rm -f "$original_args_file"

    if [ "$replaced" -eq 0 ]; then
        rebuilt_args_file="$(mktemp /tmp/test_args_rebuilt.XXXXXX)"
        for arg in "$@"; do
            append_line "$arg" >>"$rebuilt_args_file"
        done

        first_arg="$(sed -n '1p' "$rebuilt_args_file")"
        second_arg="$(sed -n '2p' "$rebuilt_args_file")"
        third_arg="$(sed -n '3p' "$rebuilt_args_file")"
        fourth_arg="$(sed -n '4p' "$rebuilt_args_file")"

        insertion_after=1
        case "$second_arg:$third_arg:$fourth_arg" in
            uboot:audit:*)
                insertion_after=3
                ;;
            efi:orom:pull|efi:orom:list|bios:orom:pull|bios:orom:list)
                insertion_after=4
                ;;
            uboot:image:pull|uboot:image:find-address|uboot:image:list-commands)
                insertion_after=1
                ;;
            uboot:image:*)
                insertion_after=3
                ;;
            *)
                insertion_after=1
                ;;
        esac

        set --
        line_no=0
        inserted=0
        while IFS= read -r arg; do
            line_no="$(expr "$line_no" + 1)"
            set -- "$@" "$arg"
            if [ "$inserted" -eq 0 ] && [ "$line_no" -eq "$insertion_after" ]; then
                set -- "$@" "$override_flag" "$override_value"
                inserted=1
            fi
        done <"$rebuilt_args_file"

        if [ "$inserted" -eq 0 ]; then
            set -- "$@" "$override_flag" "$override_value"
        fi

        rm -f "$rebuilt_args_file"
    fi

    "$@"
}

print_section() {
    title="$1"
    if has_printf; then
        printf '\n==== %s ====\n' "$title"
    else
        echo
        echo "==== $title ===="
    fi
}

require_binary() {
    bin="$1"
    if [ ! -x "$bin" ]; then
        echo "error: missing executable: $bin"
        echo "hint: build first with: make"
        exit 1
    fi

    # Reset any persisted config from previous runs so tests start from a
    # known state.  /tmp/.ela.conf survives between test scripts and can
    # cause later scripts to inherit --remote or --output-http values saved
    # by earlier tests, producing wrong exit codes or hangs.  Suppress the
    # error if the file is owned by another user (e.g. a prior sudo QEMU
    # run); the qemu test runner cleans it up via run_host_command before
    # invoking each shell test script.
    rm -f /tmp/.ela.conf 2>/dev/null || true

    ela_ensure_command python3 >/dev/null 2>&1 || true

    if command_exists zig || "$bin" --help 2>/dev/null | grep -qi 'zig'; then
        ela_ensure_command llvm-objcopy >/dev/null 2>&1 || true
    fi
}

run_exact_case() {
    name="$1"
    expected_rc="$2"
    shift 2

    log="$(mktemp /tmp/test_log.XXXXXX)"
    if [ "$expected_rc" -eq 2 ]; then
        TEST_DISABLE_OUTPUT_OVERRIDE=1 run_with_output_override "$@" >"$log" 2>&1
    else
        run_with_output_override "$@" >"$log" 2>&1
    fi
    rc=$?

    if [ "$rc" -eq "$expected_rc" ]; then
        echo "[PASS] $name (rc=$rc)"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] $name (rc=$rc, expected=$expected_rc)"
        print_file_head_scrubbed "$log" 80
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi

    rm -f "$log"
}

run_accept_case() {
    name="$1"
    shift

    log="$(mktemp /tmp/test_log.XXXXXX)"
    run_with_output_override "$@" >"$log" 2>&1
    rc=$?

    if [ "$rc" -ne 2 ]; then
        echo "[PASS] $name (rc=$rc)"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] $name (rc=$rc, parser/usage failure)"
        print_file_head_scrubbed "$log" 80
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi

    rm -f "$log"
}

finish_tests() {
    echo
    echo "Passed: $PASS_COUNT"
    echo "Failed: $FAIL_COUNT"
    [ "$FAIL_COUNT" -eq 0 ]
}
