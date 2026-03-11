#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "mips64-le" "qemu-mips64el-static" "qemu-mips64el" "$@"