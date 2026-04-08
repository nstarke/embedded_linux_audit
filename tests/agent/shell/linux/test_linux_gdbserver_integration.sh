#!/bin/sh
# Integration tests for "linux gdbserver" command.
#
# Tests the full GDB RSP session: software breakpoints, stepi, register
# read/write, memory examination, and hardware watchpoints.
#
# Prerequisites:
#   - gdb-multiarch must be on PATH
#   - The test user must have ptrace permissions (or run as root)
#
# Usage:
#   BIN=/path/to/embedded_linux_audit sh test_linux_gdbserver_integration.sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

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

TEST_OUTPUT_HTTP="${TEST_OUTPUT_HTTP:-}"
export TEST_OUTPUT_HTTP

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"

# -------------------------------------------------------------------------
# Prerequisite checks
# -------------------------------------------------------------------------

if ! command -v gdb-multiarch >/dev/null 2>&1; then
    echo "SKIP: gdb-multiarch not found in PATH"
    exit 0
fi

print_section "linux gdbserver integration tests"

# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

GDB_PORT=19100
LOOP_PID=
LOOP_BIN=/tmp/ela_test_gdbserver_loop

# Compile the target loop program once.
compile_loop_target() {
    if [ ! -x "$LOOP_BIN" ]; then
        cat > /tmp/ela_test_gdbserver_loop.c << 'EOF'
#include <time.h>
int main(void) {
    struct timespec ts = {0, 100000000}; /* 100 ms */
    for (;;) nanosleep(&ts, NULL);
    return 0;
}
EOF
        gcc -O0 -o "$LOOP_BIN" /tmp/ela_test_gdbserver_loop.c || return 1
    fi
}

start_loop() {
    "$LOOP_BIN" &
    LOOP_PID=$!
}

stop_loop() {
    if [ -n "$LOOP_PID" ]; then
        kill "$LOOP_PID" 2>/dev/null || true
        wait "$LOOP_PID" 2>/dev/null || true
        LOOP_PID=
    fi
}

next_port() {
    GDB_PORT="$(expr "$GDB_PORT" + 1)"
    echo "$GDB_PORT"
}

# Start gdbserver on $1 (PID) and $2 (port), capturing output to $3 (log).
# Waits briefly for the server to be ready.
start_gdbserver() {
    _pid="$1" _port="$2" _log="$3"
    "$BIN" linux gdbserver "$_pid" "$_port" > "$_log" 2>&1 &
    sleep 0.4
}

# Run gdb-multiarch --nx --batch with the given -ex commands (as a single
# quoted string, one command per line).  Returns gdb's exit code.
# stdout/stderr are captured in /tmp/ela_gdb_out.XXXXXX (printed on failure).
run_gdb() {
    _port="$1"
    _commands="$2"
    _outfile="$(mktemp /tmp/ela_gdb_out.XXXXXX)"

    # Build -ex arguments from newline-separated commands
    _args=""
    _IFS="$IFS"
    IFS='
'
    for _cmd in $_commands; do
        _args="$_args -ex $(printf '%s' "$_cmd" | sed "s/'/'\\\\''/g; s/^/'/; s/$/'/")"
    done
    IFS="$_IFS"

    eval "timeout 30 gdb-multiarch --nx -batch -ex 'target remote :$_port' $_args" \
        > "$_outfile" 2>&1
    _rc=$?
    echo "$_outfile"
    return $_rc
}

# Assert that a file contains a given pattern.
assert_output_contains() {
    _name="$1" _file="$2" _pattern="$3"
    if grep -qE "$_pattern" "$_file" 2>/dev/null; then
        echo "[PASS] $_name"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] $_name — pattern not found: $_pattern"
        head -40 "$_file"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
}

assert_output_not_contains() {
    _name="$1" _file="$2" _pattern="$3"
    if ! grep -qE "$_pattern" "$_file" 2>/dev/null; then
        echo "[PASS] $_name"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] $_name — unexpected pattern found: $_pattern"
        head -40 "$_file"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
}

# -------------------------------------------------------------------------
# Set up target process
# -------------------------------------------------------------------------

if ! compile_loop_target; then
    echo "SKIP: could not compile loop target (gcc not available?)"
    exit 0
fi

start_loop
trap 'stop_loop' EXIT INT TERM

# -------------------------------------------------------------------------
# Test: software breakpoints (Z0)
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
info registers pc
break *\$pc
info breakpoints
continue
info registers pc
delete breakpoints
detach
")"
OUT_FILE="$OUT"

assert_output_contains "swbp: breakpoint accepted"     "$OUT_FILE" "Breakpoint 1 at"
assert_output_contains "swbp: breakpoint hit"          "$OUT_FILE" "Breakpoint 1,"
assert_output_contains "swbp: info breakpoints shows 1" "$OUT_FILE" "hw breakpoint|breakpoint"
assert_output_contains "swbp: pc matches bp address"   "$OUT_FILE" "Breakpoint 1, 0x"
assert_output_contains "swbp: detach clean"            "$OUT_FILE" "detached"
assert_output_not_contains "swbp: no SIGSTOP leak"     "$OUT_FILE" "SIGSTOP"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: stepi advances PC
# -------------------------------------------------------------------------

start_loop_2() { "$LOOP_BIN" & echo $!; }

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
info registers pc
stepi
info registers pc
stepi
info registers pc
detach
")"
OUT_FILE="$OUT"

# Extract pc values — there should be 3, each on its own line starting with "pc"
PC_LINES="$(grep "^pc " "$OUT_FILE" 2>/dev/null || true)"
PC_COUNT="$(echo "$PC_LINES" | grep -c "^pc " 2>/dev/null || echo 0)"

if [ "$PC_COUNT" -ge 3 ]; then
    PC1="$(echo "$PC_LINES" | sed -n '1p' | awk '{print $2}')"
    PC2="$(echo "$PC_LINES" | sed -n '2p' | awk '{print $2}')"
    PC3="$(echo "$PC_LINES" | sed -n '3p' | awk '{print $2}')"

    if [ "$PC1" != "$PC2" ] && [ "$PC2" != "$PC3" ]; then
        echo "[PASS] stepi: each step advances PC ($PC1 -> $PC2 -> $PC3)"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] stepi: PC did not advance on every step ($PC1, $PC2, $PC3)"
        head -20 "$OUT_FILE"
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
else
    echo "[FAIL] stepi: expected 3 pc lines, got $PC_COUNT"
    head -20 "$OUT_FILE"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
assert_output_not_contains "stepi: no SIGSTOP leak" "$OUT_FILE" "SIGSTOP"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: info registers (all GP registers readable)
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
info registers
detach
")"
OUT_FILE="$OUT"

assert_output_contains "regs: rax present"  "$OUT_FILE" "^rax"
assert_output_contains "regs: rip present"  "$OUT_FILE" "^rip"
assert_output_contains "regs: rsp present"  "$OUT_FILE" "^rsp"
assert_output_contains "regs: eflags present" "$OUT_FILE" "^eflags"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: register write (set $rax)
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
set \$rax = 0xdeadbeef
info registers rax
detach
")"
OUT_FILE="$OUT"

assert_output_contains "reg-write: deadbeef visible after set" \
    "$OUT_FILE" "deadbeef|3735928559"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: memory examination (x/ packet)
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
x/8bx \$pc
detach
")"
OUT_FILE="$OUT"

assert_output_contains "mem: x/8bx returns bytes" "$OUT_FILE" "0x[0-9a-f]+:.*0x[0-9a-f]"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: hardware watchpoints (Z2 write watchpoint)
#
# Verifies that Z2 (write watchpoint) packets are accepted and that
# GDB programs the x86-64 debug registers (DR0/DR7) via PTRACE_POKEUSER.
# GDB only sends Z2 when given an explicit numeric address; using $rsp
# as the watched expression creates a GDB-side software watchpoint.
# We therefore read RSP first, then pass the literal hex address.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

RSP_OUT="$(run_gdb "$PORT" "
info registers rsp
detach
")"
WP_RSP="$(grep "^rsp " "$RSP_OUT" | awk '{print $2}')"
rm -f "$RSP_OUT" "$GS_LOG"

if [ -n "$WP_RSP" ]; then
    PORT="$(next_port)"
    GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
    start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

    OUT="$(run_gdb "$PORT" "
watch *(long*)$WP_RSP
info watchpoints
detach
")"
    OUT_FILE="$OUT"

    assert_output_contains "watchpoint: Z2 sent, hw watchpoint set" \
        "$OUT_FILE" "hw watchpoint"
    assert_output_contains "watchpoint: appears in info watchpoints" \
        "$OUT_FILE" "keep.*y"
    rm -f "$OUT_FILE" "$GS_LOG"
else
    echo "[SKIP] watchpoint test: could not read RSP"
fi

# -------------------------------------------------------------------------
finish_tests
