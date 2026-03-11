#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "powerpc-le" "qemu-ppc64le-static" "qemu-ppc64le" "$@"