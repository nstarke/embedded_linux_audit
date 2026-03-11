#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "aarch64-be" "qemu-aarch64_be-static" "qemu-aarch64_be" "$@"