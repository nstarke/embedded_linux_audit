#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "arm32-be" "qemu-armeb-static" "qemu-armeb" "$@"