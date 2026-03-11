#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "x86" "qemu-i386-static" "qemu-i386" "$@"