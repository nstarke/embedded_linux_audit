#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "riscv64" "qemu-riscv64-static" "qemu-riscv64" "$@"