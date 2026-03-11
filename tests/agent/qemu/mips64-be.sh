#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "mips64-be" "qemu-mips64-static" "qemu-mips64" "$@"