#!/bin/sh

set -u

. "$(CDPATH= cd -- "$(dirname "$0")" && pwd)/common.sh"

run_qemu_isa_tests "mips-le" "qemu-mipsel-static" "qemu-mipsel" "$@"