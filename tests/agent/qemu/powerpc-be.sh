#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "powerpc-be" "qemu-ppc-static" "qemu-ppc" "$@"