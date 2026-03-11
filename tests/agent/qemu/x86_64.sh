#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "x86_64" "qemu-x86_64-static" "qemu-x86_64" "$@"