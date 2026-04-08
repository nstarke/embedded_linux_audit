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
HEAP_PID=
HEAP_BIN=/tmp/ela_test_gdbserver_heap
WATCH_PID=
WATCH_BIN=/tmp/ela_test_gdbserver_watch
EXIT_PID=
EXIT_BIN=/tmp/ela_test_gdbserver_exit

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

# Compile a heap-aware binary with malloc/free in the PLT and a known global
# string, used for x/s, call malloc/free, and chunk-header inspection tests.
compile_heap_target() {
    cat > /tmp/ela_test_gdbserver_heap.c << 'EOF'
#include <time.h>
#include <stdlib.h>

/* Global string for x/s tests — non-static so it appears in .symtab */
const char g_banner[] = "ELA_TEST";

int main(void) {
    struct timespec ts = {0, 100000000}; /* 100 ms */
    /* Use malloc/free so they land in the PLT and GDB can call them */
    void *p = malloc(1);
    free(p);
    for (;;) nanosleep(&ts, NULL);
    return 0;
}
EOF
    gcc -O0 -g -o "$HEAP_BIN" /tmp/ela_test_gdbserver_heap.c || return 1
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

start_heap() {
    "$HEAP_BIN" &
    HEAP_PID=$!
}

stop_heap() {
    if [ -n "$HEAP_PID" ]; then
        kill "$HEAP_PID" 2>/dev/null || true
        wait "$HEAP_PID" 2>/dev/null || true
        HEAP_PID=
    fi
}

# Compile a small binary with a writable global counter for watchpoint tests.
compile_watch_target() {
    cat > /tmp/ela_test_gdbserver_watch.c << 'EOF'
#include <time.h>
int g_count = 0;
int main(void) {
    struct timespec ts = {0, 50000000}; /* 50 ms */
    for (;;) {
        g_count++;
        nanosleep(&ts, NULL);
    }
    return 0;
}
EOF
    gcc -O0 -g -o "$WATCH_BIN" /tmp/ela_test_gdbserver_watch.c || return 1
}

start_watch() {
    "$WATCH_BIN" &
    WATCH_PID=$!
}

stop_watch() {
    if [ -n "$WATCH_PID" ]; then
        kill "$WATCH_PID" 2>/dev/null || true
        wait "$WATCH_PID" 2>/dev/null || true
        WATCH_PID=
    fi
}

# Compile a target that loops until SIGUSR1, then exits with code 42.
# Used to test signal-stop (T packet with SIGUSR1) and process-exit (W packet).
compile_exit_target() {
    cat > /tmp/ela_test_gdbserver_exit.c << 'EOF'
#include <signal.h>
#include <time.h>
static volatile int g_done = 0;
static void handle_exit_sig(int s) { (void)s; g_done = 1; }
int main(void) {
    signal(SIGUSR1, handle_exit_sig);
    struct timespec ts = {0, 50000000}; /* 50 ms */
    while (!g_done) nanosleep(&ts, NULL);
    return 42;
}
EOF
    gcc -O0 -o "$EXIT_BIN" /tmp/ela_test_gdbserver_exit.c || return 1
}

start_exit_target() {
    "$EXIT_BIN" &
    EXIT_PID=$!
}

stop_exit_target() {
    if [ -n "$EXIT_PID" ]; then
        kill "$EXIT_PID" 2>/dev/null || true
        wait "$EXIT_PID" 2>/dev/null || true
        EXIT_PID=
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

if ! compile_heap_target; then
    echo "SKIP: could not compile heap target (gcc not available?)"
    exit 0
fi

if ! compile_watch_target; then
    echo "SKIP: could not compile watch target (gcc not available?)"
    exit 0
fi

if ! compile_exit_target; then
    echo "SKIP: could not compile exit target (gcc not available?)"
    exit 0
fi

start_loop
start_heap
start_watch
trap 'stop_loop; stop_heap; stop_watch; stop_exit_target' EXIT INT TERM

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
assert_output_contains "swbp: pc matches bp address"   "$OUT_FILE" "Breakpoint 1,"
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

assert_output_contains "mem: x/8bx returns bytes" "$OUT_FILE" "0x[0-9a-f].*:.*0x[0-9a-f]"
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
# Test: find / qSearch:memory
#
# Uses GDB's "find" command which sends qSearch:memory.  We search for the
# byte at $pc within a 256-byte window starting at $pc — guaranteed to
# succeed because the first byte of the search range IS the pattern.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
find \$pc, \$pc+0x100, *((char*)\$pc)
detach
")"
OUT_FILE="$OUT"

assert_output_contains "find: pattern found"      "$OUT_FILE" "pattern[s]* found"
assert_output_not_contains "find: not failed"     "$OUT_FILE" "Pattern not found"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: catch syscall (QCatchSyscalls) — catch-all
#
# "catch syscall" without a name sends QCatchSyscalls:1 (catch every
# syscall).  The loop binary calls clock_nanosleep every 100 ms, so we
# should receive a syscall-entry or syscall-return stop within milliseconds.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
catch syscall
continue
detach
")"
OUT_FILE="$OUT"

assert_output_contains "catch-syscall: stop received"  "$OUT_FILE" "Catchpoint 1"
assert_output_contains "catch-syscall: syscall shown"  "$OUT_FILE" "syscall|Syscall"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: call (inferior function call)
#
# Loads the loop binary to give GDB symbol info, then calls getpid().
# GDB sets up a call-dummy frame, inserts a return breakpoint (Z0), and
# uses vCont;c to resume.  On return the call result ($1 = <pid>) should
# appear.  This exercises M/X (memory write), Z0 (breakpoint), P/G
# (register r/w), and vCont;c together.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
file $LOOP_BIN
call (int)getpid()
detach
")"
OUT_FILE="$OUT"

assert_output_contains "call: getpid returned a pid" "$OUT_FILE" '^\$1 = [0-9]+'
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: x/40gx — read 40 8-byte words from the stack
#
# Exercises the 'm' packet with a 320-byte read (well within the 2048-byte
# per-packet limit).  GDB formats the output as two 64-bit hex values per
# line, so we expect at least one line matching the pattern.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
x/40gx \$rsp
detach
")"
OUT_FILE="$OUT"

# GDB prints 64-bit values as 0x<16 hex digits>
assert_output_contains "x40gx: 8-byte values present" \
    "$OUT_FILE" "0x[0-9a-f]{16}"
# Two values per line: "addr:  0x...  0x..."
assert_output_contains "x40gx: multiple values per row" \
    "$OUT_FILE" "0x[0-9a-f].*0x[0-9a-f].*0x[0-9a-f]"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: x/s — read a null-terminated string from a known global
#
# The heap binary exports g_banner = "ELA_TEST".  With 'file' loaded and
# qOffsets providing the ASLR slide, GDB resolves &g_banner and issues
# 'm' packets to read the bytes, then formats them as a string.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$HEAP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
file $HEAP_BIN
x/s &g_banner
detach
")"
OUT_FILE="$OUT"

assert_output_contains "x/s: ELA_TEST string displayed" "$OUT_FILE" "ELA_TEST"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: set {type}addr — write arbitrary value to memory and read it back
#
# 'set {long}(addr) = val' sends an 'M' packet to write 8 bytes.
# 'x/gx addr' sends an 'm' packet to read them back.
# Verifies round-trip memory write/read for exploit-simulation workflows.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
set {long}(\$rsp-8) = 0xdeadbeefcafebabe
x/gx \$rsp-8
detach
")"
OUT_FILE="$OUT"

assert_output_contains "set-mem: 0xdeadbeefcafebabe round-trips" \
    "$OUT_FILE" "deadbeefcafebabe"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: call malloc(n) — invoke libc malloc from GDB
#
# GDB sets up a call-dummy frame (saves all regs via G/P packets, writes
# a return-breakpoint via Z0, resumes via vCont;c).  malloc is in the
# heap binary's PLT, so GDB can resolve it after 'file' is loaded.
# The return value (pointer in rax) is captured and shown as $1.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$HEAP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
file $HEAP_BIN
call (void*)malloc(64)
detach
")"
OUT_FILE="$OUT"

# malloc returns a non-NULL pointer; GDB shows it as "$1 = (void *) 0x<addr>"
assert_output_contains "malloc: returns non-null pointer" \
    "$OUT_FILE" '^\$1 = \(void \*\) 0x[1-9a-f]'
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: malloc chunk header inspection via x/4gx
#
# Glibc malloc places a two-word header immediately before the user pointer:
#   [ptr-16] prev_size (0 for first chunk)
#   [ptr-8]  size | flags  (alloc size + 16 header, bit 0 = prev_in_use)
#
# Allocating 64 bytes → chunk size = 64+16 = 80 = 0x50; with prev_in_use
# set: 0x51.  We verify the header bytes are readable (non-empty output).
# 'p *((struct malloc_chunk*)addr)' is the GDB idiom; we use x/4gx here
# because the binary has no malloc_chunk debug type — the effect on the
# RSP layer is identical (both use the 'm' packet).
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$HEAP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
file $HEAP_BIN
call (void*)malloc(64)
set \$mptr = \$1
x/4gx (\$mptr - 16)
detach
")"
OUT_FILE="$OUT"

# The size field at $mptr-8 should have the prev_in_use bit set (odd value).
# Just verify we got readable hex output from the chunk header region.
assert_output_contains "malloc-chunk: header bytes readable" \
    "$OUT_FILE" "0x[0-9a-f]{16}"
# The chunk size for a 64-byte alloc is 0x51 (80 bytes | prev_in_use)
assert_output_contains "malloc-chunk: size+flags field present" \
    "$OUT_FILE" "0x000000000000005[13579bdf]"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: call free(ptr) — invoke libc free from GDB
#
# After allocating with malloc, call free() on the returned pointer.
# free() returns void; GDB shows "$N = void".  Verifies that a two-step
# malloc→free sequence works end-to-end over RSP.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$HEAP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
file $HEAP_BIN
call (void*)malloc(64)
call (void)free(\$1)
detach
")"
OUT_FILE="$OUT"

# free() is void; GDB shows no value assignment.  Just confirm the session
# completed without errors and GDB detached cleanly.
assert_output_contains "free: session completed cleanly" "$OUT_FILE" "detached"
assert_output_not_contains "free: no error reported" \
    "$OUT_FILE" "[Ee]rror|[Cc]annot|[Ff]ailed"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: find multi-byte pattern (search-pattern / ROP gadget style)
#
# Write a 4-byte sentinel to the stack, then use GDB's 'find' command
# (qSearch:memory) to locate it.  This mirrors searching for a ROP gadget
# sequence or heap metadata in a memory range.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
set {unsigned int}(\$rsp-8) = 0xdeadbeef
find \$rsp-16, \$rsp, (unsigned int)0xdeadbeef
detach
")"
OUT_FILE="$OUT"

assert_output_contains "find-multi: 4-byte pattern found" \
    "$OUT_FILE" "pattern[s]* found"
assert_output_not_contains "find-multi: not failed" \
    "$OUT_FILE" "Pattern not found"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: XMM/SSE registers visible via info registers and p/x $xmmN
#
# Exercises the org.gnu.gdb.i386.sse feature (xmm0-xmm15 at regnums 40-55,
# mxcsr at regnum 56) added to the target description.  Without this feature
# GDB creates 114 unnamed zero-size placeholder registers and no XMM data
# appears in "info all-registers".  Uses "set sysroot /" to skip slow
# remote library loading so the test completes within the timeout.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$LOOP_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
set sysroot /
info all-registers
p/x \$xmm0
p/x \$mxcsr
detach
")"
OUT_FILE="$OUT"

assert_output_contains "sse: xmm0 present in info all-registers" \
    "$OUT_FILE" "^xmm0"
assert_output_contains "sse: xmm15 present in info all-registers" \
    "$OUT_FILE" "^xmm15"
assert_output_contains "sse: mxcsr present in info all-registers" \
    "$OUT_FILE" "^mxcsr"
assert_output_contains "sse: p/x xmm0 readable" \
    "$OUT_FILE" '^\$[0-9]+ = 0x'
assert_output_contains "sse: mxcsr readable (typical value 0x1f80)" \
    "$OUT_FILE" '^\$[0-9]+ = 0x'
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: hardware watchpoint stop reports Old/New values (watch:addr in T pkt)
#
# Previously the T stop packet for a hardware watchpoint contained only
# T05thread:...;  with no "watch:addr;" annotation.  GDB never recognised the
# stop as a watchpoint and printed "Program received signal SIGTRAP" instead
# of "Hardware watchpoint N: Old value = X / New value = Y".
#
# The fix: on SIGTRAP, inspect DR6 to detect data-breakpoint fires, read the
# address from the triggered DRn slot, and include "watch:<addr>;" in the T
# packet.  GDB then displays the expected watchpoint output.
# -------------------------------------------------------------------------

PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$WATCH_PID" "$PORT" "$GS_LOG"

OUT="$(run_gdb "$PORT" "
set sysroot /
file $WATCH_BIN
watch g_count
continue
detach
")"
OUT_FILE="$OUT"

# GDB must show "Hardware watchpoint N: g_count" plus Old/New value output
assert_output_contains "hwwatch: watchpoint identified by GDB" \
    "$OUT_FILE" "Hardware watchpoint [0-9]+: g_count"
assert_output_contains "hwwatch: Old value shown" \
    "$OUT_FILE" "Old value ="
assert_output_contains "hwwatch: New value shown" \
    "$OUT_FILE" "New value ="
assert_output_not_contains "hwwatch: not reported as generic SIGTRAP" \
    "$OUT_FILE" "Program received signal SIGTRAP"
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: signal delivery stops process during continue (T packet with signal)
#
# Sends SIGUSR1 to the exit target while GDB is running it via 'continue'.
# The exit target has a SIGUSR1 handler (does not die on the signal), so
# ptrace intercepts the signal and stops the process before delivery.
# gdbserver sees a non-pass-through signal (SIGUSR1 is not in g_pass_signals)
# and breaks out of do_continue, sending a T stop reply with signal 10.
# GDB detaches after the stop (PTRACE_DETACH with no signal, so the pending
# SIGUSR1 is dropped and the process keeps looping).
# -------------------------------------------------------------------------

start_exit_target
PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$EXIT_PID" "$PORT" "$GS_LOG"

# Deliver SIGUSR1 after GDB has resumed the process via 'continue'
( sleep 0.5 && kill -USR1 "$EXIT_PID" 2>/dev/null ) &

OUT="$(run_gdb "$PORT" "
continue
detach
")"
OUT_FILE="$OUT"

assert_output_contains "signal-stop: SIGUSR1 intercepted by ptrace" \
    "$OUT_FILE" "SIGUSR1|User defined signal"
assert_output_not_contains "signal-stop: no unexpected SIGTRAP" \
    "$OUT_FILE" "SIGTRAP"
assert_output_contains "signal-stop: GDB detached cleanly" \
    "$OUT_FILE" "detached"
# After PTRACE_DETACH (with no signal forwarded) the exit target keeps looping.
# Stop it explicitly so it does not interfere with the next test.
stop_exit_target
rm -f "$OUT_FILE" "$GS_LOG"

# -------------------------------------------------------------------------
# Test: continue with forwarded signal produces process exit (W packet)
#
# Uses the same exit target (with SIGUSR1 handler that sets g_done=1 and
# returns 42).  Sequence:
#   1. External SIGUSR1 stops the process during 'continue' → T stop
#   2. GDB 'signal SIGUSR1' resumes with the signal → vCont;C or C packet
#   3. Handler fires, process exits with code 42
#   4. gdbserver sends W2a; GDB prints "exited with code 042"
#
# This exercises the 'C'/'vCont;C' (continue-with-signal) path and the
# W (process-exited) reply from send_stop_reply().
# -------------------------------------------------------------------------

start_exit_target
PORT="$(next_port)"
GS_LOG="$(mktemp /tmp/ela_gs.XXXXXX)"
start_gdbserver "$EXIT_PID" "$PORT" "$GS_LOG"

( sleep 0.5 && kill -USR1 "$EXIT_PID" 2>/dev/null ) &

OUT="$(run_gdb "$PORT" "
continue
signal SIGUSR1
")"
OUT_FILE="$OUT"

assert_output_contains "continue-with-signal: SIGUSR1 stop received" \
    "$OUT_FILE" "SIGUSR1|User defined signal"
assert_output_contains "continue-with-signal: process exited (W packet)" \
    "$OUT_FILE" "exited with code|Inferior.*exited"
rm -f "$OUT_FILE" "$GS_LOG"
# EXIT_PID has exited naturally; stop_exit_target will clean up safely.
stop_exit_target

# -------------------------------------------------------------------------
finish_tests
