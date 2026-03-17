#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "powerpc64-be" "qemu-ppc64-static" "qemu-ppc64" "$@"
