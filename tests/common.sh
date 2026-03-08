#!/usr/bin/env bash

set -u

PASS_COUNT=0
FAIL_COUNT=0

print_section() {
    local title="$1"
    printf '\n==== %s ====\n' "$title"
}

require_binary() {
    local bin="$1"
    if [[ ! -x "$bin" ]]; then
        echo "error: missing executable: $bin"
        echo "hint: build first with: make"
        exit 1
    fi
}

run_exact_case() {
    local name="$1"
    local expected_rc="$2"
    shift 2

    local log
    log="$(mktemp)"
    "$@" >"$log" 2>&1
    local rc=$?

    if [[ $rc -eq $expected_rc ]]; then
        echo "[PASS] $name (rc=$rc)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "[FAIL] $name (rc=$rc, expected=$expected_rc)"
        sed -n '1,80p' "$log"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    rm -f "$log"
}

run_accept_case() {
    local name="$1"
    shift

    local log
    log="$(mktemp)"
    "$@" >"$log" 2>&1
    local rc=$?

    if [[ $rc -ne 2 ]]; then
        echo "[PASS] $name (rc=$rc)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "[FAIL] $name (rc=$rc, parser/usage failure)"
        sed -n '1,80p' "$log"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    rm -f "$log"
}

finish_tests() {
    echo
    echo "Passed: $PASS_COUNT"
    echo "Failed: $FAIL_COUNT"
    [[ $FAIL_COUNT -eq 0 ]]
}
