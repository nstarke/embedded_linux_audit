#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SHELL_TEST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${BIN:-/tmp/embedded_linux_audit}"

# shellcheck source=tests/agent/shell/common.sh
. "$SHELL_TEST_ROOT/common.sh"

require_binary "$BIN"
print_section "linux modules buildinfo coverage"

fake_module="$(mktemp /tmp/ela-fake-module.XXXXXX.ko)"
printf 'not an elf\0license=GPL\0vermagic=6.1.0-test SMP preempt mod_unload x86_64\0name=demo\0' >"$fake_module"

# Fixture tree standing in for the host's /proc and /boot, selected via
# ELA_BUILDINFO_ROOT. config.gz is just recognizable bytes; the agent uploads
# it verbatim without decompressing.
buildinfo_root="$(mktemp -d /tmp/ela-buildinfo-root.XXXXXX)"
mkdir -p "$buildinfo_root/proc" "$buildinfo_root/boot"
printf 'Linux version 6.1.0-test (gcc 12) #1 SMP\n' >"$buildinfo_root/proc/version"
printf 'FAKE-GZ-CONFIG-BYTES' >"$buildinfo_root/proc/config.gz"

buildinfo_root_boot_only="$(mktemp -d /tmp/ela-buildinfo-boot.XXXXXX)"
mkdir -p "$buildinfo_root_boot_only/proc" "$buildinfo_root_boot_only/boot"
printf 'Linux version 6.1.0-test (gcc 12) #1 SMP\n' >"$buildinfo_root_boot_only/proc/version"
printf 'CONFIG_MODULES=y\n' >"$buildinfo_root_boot_only/boot/config-$(uname -r)"

buildinfo_root_empty="$(mktemp -d /tmp/ela-buildinfo-empty.XXXXXX)"
mkdir -p "$buildinfo_root_empty/proc" "$buildinfo_root_empty/boot"

trap 'rm -f "$fake_module"; rm -rf "$buildinfo_root" "$buildinfo_root_boot_only" "$buildinfo_root_empty"' EXIT INT TERM

run_exact_case "linux modules buildinfo --help" 0 "$BIN" linux modules buildinfo --help
run_exact_case "linux modules buildinfo extra arg" 2 "$BIN" linux modules buildinfo "$fake_module" extra

ELA_BUILDINFO_ROOT="$buildinfo_root"
export ELA_BUILDINFO_ROOT

run_exact_case "linux modules buildinfo" 0 "$BIN" linux modules buildinfo "$fake_module"
run_exact_case "linux modules buildinfo json" 0 "$BIN" --output-format json linux modules buildinfo "$fake_module"
run_exact_case "linux modules buildinfo csv" 0 "$BIN" --output-format csv linux modules buildinfo "$fake_module"

# Missing module path is not fatal: buildinfo still reports release/config.
modroot_empty="$(mktemp -d /tmp/ela-modroot-empty.XXXXXX)"
ELA_MODULE_SEARCH_ROOT="$modroot_empty"
export ELA_MODULE_SEARCH_ROOT
run_exact_case "linux modules buildinfo no .ko still succeeds" 0 "$BIN" linux modules buildinfo
unset ELA_MODULE_SEARCH_ROOT
rmdir "$modroot_empty"

buildinfo_log="$(mktemp /tmp/test_linux_modules_buildinfo.XXXXXX)"
"$BIN" --output-format json linux modules buildinfo "$fake_module" >"$buildinfo_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -q '"record":"module_buildinfo"' "$buildinfo_log" && \
   grep -q '"vermagic":"6.1.0-test SMP preempt mod_unload x86_64"' "$buildinfo_log" && \
   grep -q '"proc_version":"Linux version 6.1.0-test (gcc 12) #1 SMP"' "$buildinfo_log" && \
   grep -q '"config_available":true,"config_compressed":true' "$buildinfo_log"; then
    echo "[PASS] linux modules buildinfo emits kernel and config facts"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux modules buildinfo emits kernel and config facts (rc=$rc)"
    print_file_head_scrubbed "$buildinfo_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$buildinfo_log"

# /boot/config-$(uname -r) is the fallback when /proc/config.gz is absent.
buildinfo_log="$(mktemp /tmp/test_linux_modules_buildinfo.XXXXXX)"
ELA_BUILDINFO_ROOT="$buildinfo_root_boot_only" "$BIN" --output-format json \
    linux modules buildinfo "$fake_module" >"$buildinfo_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -q '"config_source":".*/boot/config-' "$buildinfo_log" && \
   grep -q '"config_available":true,"config_compressed":false' "$buildinfo_log"; then
    echo "[PASS] linux modules buildinfo falls back to /boot config"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux modules buildinfo falls back to /boot config (rc=$rc)"
    print_file_head_scrubbed "$buildinfo_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$buildinfo_log"

# No config anywhere: still exit 0, report config_available false.
buildinfo_log="$(mktemp /tmp/test_linux_modules_buildinfo.XXXXXX)"
ELA_BUILDINFO_ROOT="$buildinfo_root_empty" "$BIN" --output-format json \
    linux modules buildinfo "$fake_module" >"$buildinfo_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -q '"config_source":null' "$buildinfo_log" && \
   grep -q '"config_available":false' "$buildinfo_log"; then
    echo "[PASS] linux modules buildinfo reports missing config"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] linux modules buildinfo reports missing config (rc=$rc)"
    print_file_head_scrubbed "$buildinfo_log" 40
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -f "$buildinfo_log"

# With no fixture root and no /proc/config.gz, buildinfo attempts
# `modprobe configs` (IKCONFIG=m kernels) before scanning candidates. Prove it
# via a PATH-stubbed modprobe that records its arguments. Only valid when the
# host really lacks /proc/config.gz — skip otherwise (the attempt is
# correctly bypassed there).
if [ ! -r /proc/config.gz ]; then
    stub_dir="$(mktemp -d /tmp/ela-modprobe-stub.XXXXXX)"
    marker="$stub_dir/invoked"
    cat >"$stub_dir/modprobe" <<STUB
#!/bin/sh
echo "\$@" >> "$marker"
exit 0
STUB
    chmod +x "$stub_dir/modprobe"
    unset ELA_BUILDINFO_ROOT
    PATH="$stub_dir:$PATH" "$BIN" linux modules buildinfo "$fake_module" >/dev/null 2>&1
    if [ -f "$marker" ] && grep -q "configs" "$marker"; then
        echo "[PASS] linux modules buildinfo attempts modprobe configs"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] linux modules buildinfo attempts modprobe configs"
        ls -la "$stub_dir" 2>/dev/null
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
    ELA_BUILDINFO_ROOT="$buildinfo_root"
    export ELA_BUILDINFO_ROOT
    rm -rf "$stub_dir"
else
    echo "[SKIP] linux modules buildinfo attempts modprobe configs (/proc/config.gz present)"
fi

# Under a fixture root the modprobe attempt must be bypassed entirely.
stub_dir="$(mktemp -d /tmp/ela-modprobe-stub.XXXXXX)"
marker="$stub_dir/invoked"
cat >"$stub_dir/modprobe" <<STUB
#!/bin/sh
echo "\$@" >> "$marker"
exit 0
STUB
chmod +x "$stub_dir/modprobe"
PATH="$stub_dir:$PATH" ELA_BUILDINFO_ROOT="$buildinfo_root_empty" \
    "$BIN" linux modules buildinfo "$fake_module" >/dev/null 2>&1
if [ ! -f "$marker" ]; then
    echo "[PASS] fixture root bypasses modprobe configs"
    PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
else
    echo "[FAIL] fixture root bypasses modprobe configs"
    cat "$marker"
    FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
fi
rm -rf "$stub_dir"

# Over HTTP the command POSTs twice: the buildinfo JSON, then the raw config
# bytes as kernel-config.
http_req_path="$(mktemp /tmp/test_modules_buildinfo_http_path.XXXXXX)"
http_req_type="$(mktemp /tmp/test_modules_buildinfo_http_type.XXXXXX)"
http_req_body="$(mktemp /tmp/test_modules_buildinfo_http_body.XXXXXX)"
http_server_log="$(mktemp /tmp/test_modules_buildinfo_http_server.XXXXXX)"
http_cmd_log="$(mktemp /tmp/test_modules_buildinfo_http_cmd.XXXXXX)"
python_bin="$(find_python_bin || true)"
http_server_pid=""
http_port=""
if [ -n "$python_bin" ]; then
    "$python_bin" "$SCRIPT_DIR/http_capture_server.py" \
        --path-out "$http_req_path" \
        --type-out "$http_req_type" \
        --body-out "$http_req_body" \
        --count 2 \
        --status 200 >"$http_server_log" 2>&1 &
    http_server_pid=$!
    http_port="$(wait_for_http_capture_server_ready "$http_server_log" || true)"
fi
if [ -n "$http_port" ]; then
    TEST_DISABLE_OUTPUT_OVERRIDE=1 "$BIN" --output-format json \
        --output-http "http://127.0.0.1:$http_port" \
        linux modules buildinfo "$fake_module" >"$http_cmd_log" 2>&1
    rc=$?
    wait "$http_server_pid" 2>/dev/null || true
    if [ "$rc" -eq 0 ] && \
       grep -F "/upload/module-buildinfo" "$http_req_path.0" >/dev/null 2>&1 && \
       grep -F "application/json; charset=utf-8" "$http_req_type.0" >/dev/null 2>&1 && \
       grep -F '"record":"module_buildinfo"' "$http_req_body.0" >/dev/null 2>&1 && \
       grep -F "/upload/kernel-config" "$http_req_path.1" >/dev/null 2>&1 && \
       grep -F "application/octet-stream" "$http_req_type.1" >/dev/null 2>&1 && \
       grep -F 'FAKE-GZ-CONFIG-BYTES' "$http_req_body.1" >/dev/null 2>&1; then
        echo "[PASS] linux modules buildinfo posts buildinfo and kernel config"
        PASS_COUNT="$(expr "$PASS_COUNT" + 1)"
    else
        echo "[FAIL] linux modules buildinfo posts buildinfo and kernel config (rc=$rc)"
        print_file_head_scrubbed "$http_cmd_log" 80
        for suffix in 0 1; do
            echo "--- request $suffix path ---"
            print_file_head_scrubbed "$http_req_path.$suffix" 20
            echo "--- request $suffix type ---"
            print_file_head_scrubbed "$http_req_type.$suffix" 20
            echo "--- request $suffix body ---"
            print_file_head_scrubbed "$http_req_body.$suffix" 40
        done
        FAIL_COUNT="$(expr "$FAIL_COUNT" + 1)"
    fi
else
    echo "[SKIP] linux modules buildinfo posts buildinfo and kernel config (python HTTP capture unavailable)"
fi
if [ -n "$http_server_pid" ]; then
    stop_background_server "$http_server_pid"
fi
rm -f "$http_req_path" "$http_req_type" "$http_req_body" \
    "$http_req_path".* "$http_req_type".* "$http_req_body".* \
    "$http_server_log" "$http_cmd_log"

finish_tests
