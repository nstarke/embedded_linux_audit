#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux audit subcommand argument coverage"

run_exact_case "linux audit --help" 0 "$BIN" linux audit --help
run_exact_case "linux audit all invalid option" 2 "$BIN" linux audit all --invalid
run_accept_case "linux audit all unavailable root" "$BIN" linux audit all --quick --root /path/that/does/not/exist
run_exact_case "linux audit list rules" 0 "$BIN" linux audit --list-rules
run_exact_case "linux audit invalid profile" 2 "$BIN" linux audit --profile invalid
run_exact_case "linux audit unknown rule" 2 "$BIN" linux audit --rule ELA-LINUX-999
run_exact_case "linux audit rule outside profile" 2 "$BIN" linux audit --rule ELA-LINUX-008
run_exact_case "linux audit relative root" 2 "$BIN" linux audit --root relative
run_exact_case "linux audit extra arg" 2 "$BIN" linux audit extra
run_exact_case "linux audit filesystem help" 0 "$BIN" linux audit filesystem --help
run_exact_case "linux audit filesystem relative root" 2 "$BIN" linux audit filesystem --root relative
run_accept_case "linux audit filesystem quick" "$BIN" linux audit filesystem --quick --root /path/that/does/not/exist
run_exact_case "linux audit persistence help" 0 "$BIN" linux audit persistence --help
run_exact_case "linux audit persistence relative root" 2 "$BIN" linux audit persistence --root relative
run_accept_case "linux audit persistence quick" "$BIN" linux audit persistence --quick --root /path/that/does/not/exist
run_exact_case "linux audit identity help" 0 "$BIN" linux audit identity --help
run_exact_case "linux audit identity relative root" 2 "$BIN" linux audit identity --root relative
run_accept_case "linux audit identity quick" "$BIN" linux audit identity --quick --root /path/that/does/not/exist
run_exact_case "linux audit network help" 0 "$BIN" linux audit network --help
run_exact_case "linux audit network relative root" 2 "$BIN" linux audit network --root relative
run_accept_case "linux audit network unavailable root" "$BIN" linux audit network --root /path/that/does/not/exist
run_exact_case "linux audit integrity help" 0 "$BIN" linux audit integrity --help
run_exact_case "linux audit integrity relative root" 2 "$BIN" linux audit integrity --root relative
run_accept_case "linux audit integrity unavailable root" "$BIN" linux audit integrity --root /path/that/does/not/exist
run_exact_case "linux audit secrets help" 0 "$BIN" linux audit secrets --help
run_exact_case "linux audit secrets relative root" 2 "$BIN" linux audit secrets --root relative
run_accept_case "linux audit secrets unavailable root" "$BIN" linux audit secrets --quick --root /path/that/does/not/exist
run_exact_case "linux audit hardware help" 0 "$BIN" linux audit hardware --help
run_exact_case "linux audit hardware relative root" 2 "$BIN" linux audit hardware --root relative
run_accept_case "linux audit hardware unavailable root" "$BIN" linux audit hardware --root /path/that/does/not/exist
run_exact_case "linux audit unavailable root is unknown" 0 "$BIN" --output-format json linux audit --root /path/that/does/not/exist --no-fail
run_accept_case "linux audit current host" "$BIN" linux audit --no-fail

audit_root="$(mktemp -d /tmp/ela-linux-audit.XXXXXX)"
trap 'rm -rf "$audit_root"' EXIT HUP INT TERM
mkdir -p "$audit_root/proc/sys/kernel"
printf '0\n' >"$audit_root/proc/sys/kernel/randomize_va_space"
run_exact_case "linux audit failed finding returns one" 1 \
    "$BIN" linux audit --rule ELA-LINUX-001 --root "$audit_root"
printf '2\n' >"$audit_root/proc/sys/kernel/randomize_va_space"
run_exact_case "linux audit passing finding returns zero" 0 \
    "$BIN" linux audit --profile hardened --rule ELA-LINUX-001 --root "$audit_root"

mkdir -p "$audit_root/proc/sys/fs"
printf '2\n' >"$audit_root/proc/sys/fs/suid_dumpable"
run_exact_case "linux audit suid_dumpable failing returns one" 1 \
    "$BIN" linux audit --rule ELA-LINUX-022 --root "$audit_root"
printf '0\n' >"$audit_root/proc/sys/fs/suid_dumpable"
run_exact_case "linux audit suid_dumpable passing returns zero" 0 \
    "$BIN" linux audit --rule ELA-LINUX-022 --root "$audit_root"

printf 'BOOT_IMAGE=/vmlinuz root=/dev/mmcblk0p2 quiet mitigations=off\n' >"$audit_root/proc/cmdline"
run_exact_case "linux audit cmdline override returns one" 1 \
    "$BIN" linux audit --rule ELA-LINUX-034 --root "$audit_root"
printf 'BOOT_IMAGE=/vmlinuz root=/dev/mmcblk0p2 quiet\n' >"$audit_root/proc/cmdline"
run_exact_case "linux audit clean cmdline returns zero" 0 \
    "$BIN" linux audit --rule ELA-LINUX-034 --root "$audit_root"

printf 'tracefs /sys/kernel/tracing tracefs rw,nosuid 0 0\n' >"$audit_root/proc/mounts"
run_exact_case "linux audit tracefs mounted returns one" 1 \
    "$BIN" linux audit --profile hardened --rule ELA-LINUX-053 --root "$audit_root"
printf 'proc /proc proc rw 0 0\n' >"$audit_root/proc/mounts"
run_exact_case "linux audit tracefs absent returns zero" 0 \
    "$BIN" linux audit --profile hardened --rule ELA-LINUX-053 --root "$audit_root"

finish_tests
