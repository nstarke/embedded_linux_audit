#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "riscv32" "qemu-riscv32-static" "qemu-riscv32" "$@"