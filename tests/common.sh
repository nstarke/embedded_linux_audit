#!/bin/sh

set -u

PASS_COUNT=0
FAIL_COUNT=0

run_with_output_override() {
    override_flag=""
    override_value=""

    if [ -n "${TEST_OUTPUT_HTTP:-}" ] && [ -n "${TEST_OUTPUT_HTTPS:-}" ]; then
        echo "error: set only one of TEST_OUTPUT_HTTP or TEST_OUTPUT_HTTPS"
        return 2
    fi

    if [ -n "${TEST_OUTPUT_HTTP:-}" ]; then
        override_flag="--output-http"
        override_value="$TEST_OUTPUT_HTTP"
    elif [ -n "${TEST_OUTPUT_HTTPS:-}" ]; then
        override_flag="--output-https"
        override_value="$TEST_OUTPUT_HTTPS"
    fi

    if [ -z "$override_flag" ]; then
        "$@"
        return $?
    fi

    original_args_file="$(mktemp /tmp/test_args.XXXXXX)"
    for arg in "$@"; do
        printf '%s\n' "$arg" >>"$original_args_file"
    done

    replaced=0
    set --
    while IFS= read -r arg; do
        case "$arg" in
            --output-http|--output-https)
                IFS= read -r _unused_next_arg || true
                set -- "$@" "$override_flag" "$override_value"
                replaced=1
                ;;
            --output-http=*|--output-https=*)
                set -- "$@" "${override_flag}=${override_value}"
                replaced=1
                ;;
            *)
                set -- "$@" "$arg"
                ;;
        esac
    done <"$original_args_file"

    rm -f "$original_args_file"

    if [ "$replaced" -eq 0 ]; then
        set -- "$@" "$override_flag" "$override_value"
    fi

    "$@"
}

print_section() {
    title="$1"
    printf '\n==== %s ====\n' "$title"
}

require_binary() {
    bin="$1"
    if [ ! -x "$bin" ]; then
        echo "error: missing executable: $bin"
        echo "hint: build first with: make"
        exit 1
    fi
}

run_exact_case() {
    name="$1"
    expected_rc="$2"
    shift 2

    log="$(mktemp)"
    run_with_output_override "$@" >"$log" 2>&1
    rc=$?

    if [ "$rc" -eq "$expected_rc" ]; then
        echo "[PASS] $name (rc=$rc)"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] $name (rc=$rc, expected=$expected_rc)"
        sed -n '1,80p' "$log"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi

    rm -f "$log"
}

run_accept_case() {
    name="$1"
    shift

    log="$(mktemp)"
    run_with_output_override "$@" >"$log" 2>&1
    rc=$?

    if [ "$rc" -ne 2 ]; then
        echo "[PASS] $name (rc=$rc)"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] $name (rc=$rc, parser/usage failure)"
        sed -n '1,80p' "$log"
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
