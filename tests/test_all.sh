#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"

usage() {
    cat <<'EOF'
Usage: tests/test_all.sh [--output-http <url>]

Runs the local repository test suites:
  - agent C unit tests
  - agent shell tests
  - agent script tests
  - API shell tests
  - API Jest tests

Options:
  --output-http URL   Forwarded to tests/agent/shell/test_all.sh
EOF
}

run_step() {
    step_name="$1"
    shift

    echo
    echo "===== Running $step_name ====="
    "$@"
    step_rc=$?
    if [ "$step_rc" -ne 0 ]; then
        rc=1
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-http)
            if [ "$#" -lt 2 ]; then
                echo "error: --output-http requires a value" >&2
                usage >&2
                exit 2
            fi
            TEST_OUTPUT_HTTP="$2"
            shift 2
            ;;
        --output-http=*)
            TEST_OUTPUT_HTTP="${1#*=}"
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

rc=0

run_step "build embedded_linux_audit" make -C "$REPO_ROOT"
run_step "build agent C unit tests" make -C "$REPO_ROOT" build-unit-agent-c
run_step "agent C unit tests" "$REPO_ROOT/generated/agent_unit_tests"

if [ -n "$TEST_OUTPUT_HTTP" ]; then
    run_step "agent shell tests" env BIN="$REPO_ROOT/embedded_linux_audit" \
        /bin/bash "$REPO_ROOT/tests/agent/shell/test_all.sh" --output-http "$TEST_OUTPUT_HTTP"
else
    run_step "agent shell tests" env BIN="$REPO_ROOT/embedded_linux_audit" \
        /bin/bash "$REPO_ROOT/tests/agent/shell/test_all.sh"
fi

run_step "agent script tests" env BIN="$REPO_ROOT/embedded_linux_audit" \
    /bin/sh "$REPO_ROOT/tests/agent/scripts/test_all.sh"
run_step "API shell tests" /bin/sh "$REPO_ROOT/tests/api/agent/test_all.sh"
run_step "API agent Jest tests" /bin/sh "$REPO_ROOT/tests/api/agent/test_jest.sh"
run_step "API terminal Jest tests" /bin/sh "$REPO_ROOT/tests/api/terminal/test_jest.sh"

exit "$rc"
