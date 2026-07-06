#!/bin/sh
# SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
#
# Integration test for api/builder/build-kernel-module.sh: fetches a real
# (small, pinned) kernel, runs modules_prepare, compiles kmod/, and asserts
# the produced .ko carries the expected vermagic.
#
# Gated because it downloads ~140MB and compiles for a few minutes:
#   ELA_RUN_BUILD_TESTS=1 sh tests/builder/test_module_build.sh
#
# Requirements: the builder image's toolchain (native gcc is enough for the
# x86_64 case; the arm64 case runs only when aarch64-linux-gnu-gcc exists).

set -u

if [ "${ELA_RUN_BUILD_TESTS:-0}" != "1" ]; then
    echo "[SKIP] module build integration (set ELA_RUN_BUILD_TESTS=1 to run)"
    exit 0
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_SCRIPT="$REPO_ROOT/api/builder/build-kernel-module.sh"

# Pinned LTS: small enough to prepare quickly, new enough for modern gcc.
KERNEL_VERSION="${ELA_TEST_KERNEL_VERSION:-6.1.90}"

PASS_COUNT=0
FAIL_COUNT=0

run_case() {
    name="$1"; arch="$2"; cross="$3"; want_release="$4"
    out_dir="$(mktemp -d /tmp/ela-kmod-out.XXXXXX)"
    log="$(mktemp /tmp/ela-kmod-build-log.XXXXXX)"

    if ELA_KMOD_KERNEL_VERSION="$KERNEL_VERSION" \
       ELA_KMOD_LOCALVERSION="-elatest" \
       ELA_KMOD_ARCH="$arch" \
       ELA_KMOD_CROSS_COMPILE="$cross" \
       ELA_KMOD_OUT_DIR="$out_dir" \
       ELA_KMOD_SRC_DIR="$REPO_ROOT/kmod" \
       ELA_KMOD_CACHE_DIR="${ELA_KMOD_CACHE_DIR:-/tmp/ela-kmod-cache}" \
       sh "$BUILD_SCRIPT" >"$log" 2>&1 \
       && [ -f "$out_dir/ela_kmod.ko" ] \
       && grep -q "^${want_release}-elatest " "$out_dir/vermagic.txt"; then
        echo "[PASS] $name (vermagic: $(cat "$out_dir/vermagic.txt"))"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "[FAIL] $name"
        tail -40 "$log"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    rm -rf "$out_dir" "$log"
}

# Native x86_64 build (defconfig path — no device config supplied).
run_case "x86_64 defconfig module build" x86_64 "" "$KERNEL_VERSION"

# Cross aarch64 build, only when the toolchain is present.
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    run_case "aarch64 cross module build" arm64 "aarch64-linux-gnu-" "$KERNEL_VERSION"
else
    echo "[SKIP] aarch64 cross module build (no aarch64-linux-gnu-gcc)"
fi

echo
echo "Passed: $PASS_COUNT"
echo "Failed: $FAIL_COUNT"
[ "$FAIL_COUNT" -eq 0 ]
