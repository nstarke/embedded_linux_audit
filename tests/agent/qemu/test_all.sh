#!/bin/bash

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RELEASE_BUILD_SCRIPT="$REPO_ROOT/tests/compile_release_binaries_locally.sh"
UNIT_TEST_BIN_DIR="$REPO_ROOT/generated/qemu_unit_tests"

# shellcheck source=tests/agent/qemu/common.sh
. "$SCRIPT_DIR/common.sh"

usage() {
    echo "Usage: $0 [--clean] [--jobs N] [qemu-test-args...]" >&2
    echo "  --clean    rebuild all release binaries before running tests" >&2
    echo "             and rebuild all per-ISA C unit test binaries" >&2
    echo "  --jobs N   run up to N ISA tests in parallel (default: 1)" >&2
    exit 1
}

rc=0
pass_count=0
fail_count=0
clean_release_binaries=0
jobs_limit=1

count_matches() {
    pattern="$1"
    log_path="$2"

    grep -c -- "$pattern" "$log_path" 2>/dev/null || true
}

unit_test_zig_targets() {
    isa="$1"

    case "$isa" in
        arm32-le) echo "arm-linux-musleabi" ;;
        arm32-be) echo "armeb-linux-musleabi,armeb-linux-gnueabi" ;;
        aarch64-le) echo "aarch64-linux-musl" ;;
        aarch64-be) echo "aarch64_be-linux-musl" ;;
        mips-le) echo "mipsel-linux-musleabi,mipsel-linux-musleabihf" ;;
        mips-be) echo "mips-linux-musleabi,mips-linux-musleabihf" ;;
        mips64-le) echo "mips64el-linux-muslabi64,mips64el-linux-gnuabi64" ;;
        mips64-be) echo "mips64-linux-muslabi64,mips64-linux-gnuabi64" ;;
        powerpc-le) echo "powerpc64le-linux-musl,powerpc64le-linux-gnu" ;;
        powerpc-be) echo "powerpc-linux-musleabi,powerpc-linux-musleabihf,powerpc-linux-gnueabi,powerpc-linux-gnueabihf" ;;
        x86) echo "x86-linux-musl" ;;
        x86_64) echo "x86_64-linux-musl" ;;
        riscv32) echo "riscv32-linux-musl,riscv32-linux-gnu" ;;
        riscv64) echo "riscv64-linux-musl,riscv64-linux-gnu" ;;
        *)
            echo ""
            return 1
            ;;
    esac
}

unit_test_bin_path() {
    isa="$1"
    echo "$UNIT_TEST_BIN_DIR/$isa/agent_unit_tests-$isa"
}

ensure_qemu_unit_test_binary() {
    isa="$1"
    clean_build="${2:-0}"
    unit_bin="$(unit_test_bin_path "$isa")"
    zig_path="$(command -v zig 2>/dev/null || true)"

    if [ "$clean_build" -ne 1 ] && [ -x "$unit_bin" ]; then
        return 0
    fi

    if [ -z "$zig_path" ]; then
        echo "error: zig is required to build per-ISA C unit test binaries for QEMU" >&2
        exit 1
    fi

    targets="$(unit_test_zig_targets "$isa")"
    if [ -z "$targets" ]; then
        echo "error: unsupported ISA for QEMU C unit test build: $isa" >&2
        exit 1
    fi

    mkdir -p "$UNIT_TEST_BIN_DIR/$isa"
    rm -f "$unit_bin"

    OLD_IFS="$IFS"
    IFS=','
    set -- $targets
    IFS="$OLD_IFS"

    for target in "$@"; do
        echo "Building QEMU C unit test binary for $isa via target $target"
        if make clean \
            && make build-unit-agent-c \
                ELA_USE_READLINE=0 \
                LDFLAGS=-static \
                UNIT_TEST_CC="zig cc -target $target" \
                UNIT_TEST_CFLAGS="-O2 -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE" \
                UNIT_TEST_LDFLAGS=-static \
                CMAKE_C_COMPILER="$zig_path" \
                CMAKE_C_COMPILER_ARG1=cc \
                CMAKE_C_COMPILER_TARGET="$target" \
                CC="zig cc -target $target"; then
            cp "$REPO_ROOT/generated/agent_unit_tests" "$unit_bin"
            chmod +x "$unit_bin"
            return 0
        fi
        echo "warning: failed building QEMU C unit test binary for $isa via target $target" >&2
    done

    echo "error: failed to build any per-ISA C unit test binary for $isa" >&2
    exit 1
}

test_script_isa() {
    test_script="$1"
    basename "$test_script" .sh
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --clean)
            clean_release_binaries=1
            shift
            ;;
        --jobs)
            if [ "$#" -lt 2 ]; then
                echo "error: --jobs requires a value" >&2
                usage
            fi
            jobs_limit="$2"
            shift 2
            ;;
        --jobs=*)
            jobs_limit="${1#*=}"
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            break
            ;;
    esac
done

case "$jobs_limit" in
    ''|*[!0-9]*)
        echo "error: --jobs value must be a positive integer: $jobs_limit" >&2
        usage
        ;;
esac
if [ "$jobs_limit" -eq 0 ]; then
    echo "error: --jobs value must be at least 1" >&2
    usage
fi

if [ "$clean_release_binaries" -eq 1 ]; then
    require_file "$RELEASE_BUILD_SCRIPT"
    build_jobs="$(cpu_jobs_for_build)"
    echo "Rebuilding all release binaries via tests/compile_release_binaries_locally.sh --clean --jobs=$build_jobs"
    if ! /bin/sh "$RELEASE_BUILD_SCRIPT" --clean --jobs="$build_jobs"; then
        echo "error: failed to rebuild release binaries" >&2
        exit 1
    fi
fi

TEST_SCRIPTS=(
    "$SCRIPT_DIR/arm32-le.sh"
    "$SCRIPT_DIR/arm32-be.sh"
    "$SCRIPT_DIR/aarch64-le.sh"
    "$SCRIPT_DIR/aarch64-be.sh"
    "$SCRIPT_DIR/mips-le.sh"
    "$SCRIPT_DIR/mips-be.sh"
    "$SCRIPT_DIR/mips64-le.sh"
    "$SCRIPT_DIR/mips64-be.sh"
    "$SCRIPT_DIR/powerpc-le.sh"
    "$SCRIPT_DIR/powerpc-be.sh"
    "$SCRIPT_DIR/x86.sh"
    "$SCRIPT_DIR/x86_64.sh"
    "$SCRIPT_DIR/riscv32.sh"
    "$SCRIPT_DIR/riscv64.sh"
)

for test_script in "${TEST_SCRIPTS[@]}"; do
    isa_name="$(test_script_isa "$test_script")"
    ensure_qemu_unit_test_binary "$isa_name" "$clean_release_binaries"
done

if [ "$jobs_limit" -eq 1 ]; then
    # Sequential: stream output in real time (original behavior)
    for test_script in "${TEST_SCRIPTS[@]}"; do
        isa_name="$(test_script_isa "$test_script")"
        unit_bin="$(unit_test_bin_path "$isa_name")"
        echo
        echo "===== Running $(basename "$test_script") ====="
        test_log="$(mktemp /tmp/ela-qemu-test-all.XXXXXX)"
        ELA_QEMU_UNIT_TEST_BIN="$unit_bin" /bin/sh "$test_script" "$@" 2>&1 | tee "$test_log"
        test_rc=${PIPESTATUS[0]}

        test_passes="$(count_matches '^\[PASS\]' "$test_log")"
        test_fails="$(count_matches '^\[FAIL\]' "$test_log")"

        if [ "$test_passes" -eq 0 ]; then
            test_passes="$(sed -n 's/^Passed: //p' "$test_log" | tail -n 1)"
        fi

        if [ "$test_fails" -eq 0 ]; then
            test_fails="$(sed -n 's/^Failed: //p' "$test_log" | tail -n 1)"
        fi

        if [ -n "$test_passes" ]; then
            pass_count="$(expr "$pass_count" + "$test_passes")"
        fi

        if [ -n "$test_fails" ]; then
            fail_count="$(expr "$fail_count" + "$test_fails")"
        fi

        rm -f "$test_log"

        if [ "$test_rc" -ne 0 ]; then
            rc=1
        fi
    done
else
    # Parallel: run up to $jobs_limit ISA tests concurrently, buffer output
    n="${#TEST_SCRIPTS[@]}"
    echo "Running $n ISA tests with up to $jobs_limit parallel jobs..."

    # Indexed arrays: one entry per ISA in launch order
    job_pids=()
    job_logs=()
    job_names=()
    job_rcs=()
    running=0

    harvest_finished() {
        local i
        for i in "${!job_pids[@]}"; do
            # Skip already-collected slots (pid set to empty)
            [ -n "${job_pids[$i]}" ] || continue
            # Skip if exit code already recorded
            [ "${job_rcs[$i]}" = "pending" ] || continue
            if ! kill -0 "${job_pids[$i]}" 2>/dev/null; then
                wait "${job_pids[$i]}" && job_rcs[$i]=0 || job_rcs[$i]=$?
                running=$((running - 1))
            fi
        done
    }

    for test_script in "${TEST_SCRIPTS[@]}"; do
        name="$(basename "$test_script")"
        isa_name="$(test_script_isa "$test_script")"
        unit_bin="$(unit_test_bin_path "$isa_name")"
        log="$(mktemp /tmp/ela-qemu-test-all.XXXXXX)"

        # Wait for a free slot
        while [ "$running" -ge "$jobs_limit" ]; do
            sleep 0.2
            harvest_finished
        done

        printf "  [starting] %s\n" "$name"
        ELA_QEMU_UNIT_TEST_BIN="$unit_bin" /bin/sh "$test_script" "$@" >"$log" 2>&1 &
        idx="${#job_pids[@]}"
        job_pids[$idx]=$!
        job_logs[$idx]="$log"
        job_names[$idx]="$name"
        job_rcs[$idx]="pending"
        running=$((running + 1))
    done

    # Wait for all remaining jobs
    for i in "${!job_pids[@]}"; do
        [ "${job_rcs[$i]}" = "pending" ] || continue
        wait "${job_pids[$i]}" && job_rcs[$i]=0 || job_rcs[$i]=$?
    done

    # Print results in ISA order and aggregate counts
    for i in "${!job_names[@]}"; do
        echo
        echo "===== ${job_names[$i]} ====="
        cat "${job_logs[$i]}"

        test_passes="$(count_matches '^\[PASS\]' "${job_logs[$i]}")"
        test_fails="$(count_matches '^\[FAIL\]' "${job_logs[$i]}")"

        if [ "$test_passes" -eq 0 ]; then
            test_passes="$(sed -n 's/^Passed: //p' "${job_logs[$i]}" | tail -n 1)"
        fi

        if [ "$test_fails" -eq 0 ]; then
            test_fails="$(sed -n 's/^Failed: //p' "${job_logs[$i]}" | tail -n 1)"
        fi

        if [ -n "$test_passes" ]; then
            pass_count="$(expr "$pass_count" + "$test_passes")"
        fi

        if [ -n "$test_fails" ]; then
            fail_count="$(expr "$fail_count" + "$test_fails")"
        fi

        rm -f "${job_logs[$i]}"

        if [ "${job_rcs[$i]}" -ne 0 ]; then
            rc=1
        fi
    done
fi

echo
echo "Total test cases passed: $pass_count"
echo "Total test cases failed: $fail_count"

exit "$rc"
