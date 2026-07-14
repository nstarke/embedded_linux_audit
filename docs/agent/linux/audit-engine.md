# Linux audit engine rule format

The `linux audit` command uses a compiled rule catalog in
`agent/linux/linux_audit_util.c`. Rules are intentionally compiled into the
static agent so an assessment does not need a policy file, shell, interpreter,
or package manager on the target.

## Rule record

Each entry is a `struct ela_linux_audit_rule`:

```c
{
    .id = "ELA-LINUX-019",
    .title = "Example control",
    .category = "kernel",
    .severity = "high",
    .description = "What security property is being checked.",
    .remediation = "How an operator should correct a failure.",
    .path = "/proc/sys/kernel/example",
    .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
    .embedded_minimum = 1,
    .hardened_minimum = 1,
},
```

`id` is a permanent machine-readable identifier. Do not reuse an ID for a
different control. `title`, `description`, and `remediation` are displayed in
text output and included in CSV/JSON output. `category` is intended for report
grouping; use values such as `kernel`, `modules`, `lsm`, `process`, `debug`, or
`filesystem`. Severity is normally `low`, `medium`, or `high`.

`profiles` is a bitmask. Use `PROFILE_BOTH` inside the implementation for a
rule that belongs to both profiles, or one of
`ELA_LINUX_AUDIT_PROFILE_EMBEDDED` and
`ELA_LINUX_AUDIT_PROFILE_HARDENED`. A rule that is not enabled by the selected
profile is skipped and does not affect the summary.

## Check types

The default check type is `ELA_LINUX_AUDIT_CHECK_INTEGER_MIN`. It reads the
integer at `path` and passes when it is at least the selected profile's
threshold:

```c
{
    .id = "ELA-LINUX-020",
    .title = "Example sysctl",
    .category = "kernel",
    .severity = "medium",
    .description = "The control must be enabled.",
    .remediation = "Set kernel.example=1.",
    .path = "/proc/sys/kernel/example",
    .profiles = PROFILE_BOTH,
    .embedded_minimum = 1,
    .hardened_minimum = 1,
}
```

Available specialized checks are:

- `ELA_LINUX_AUDIT_CHECK_INTEGER_MAX`: integer must be less than or equal to
  `expected`, for example `expected = "0"` for `kernel.sysrq`.
- `ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION`: searches plain kernel configuration
  files for the exact string in `expected`, such as
  `CONFIG_MODULE_SIG_FORCE=y`. The engine checks `/boot/config-<release>`,
  `/usr/lib/modules/<release>/config`, and `/proc/config`. Compressed
  `/proc/config.gz` is reported unknown unless a plain configuration is also
  available.
- `ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN`: reads `path` and fails when
  `expected` occurs, useful for `nokaslr`, `pti=off`, or similar boot overrides.
- `ELA_LINUX_AUDIT_CHECK_LOCKDOWN`: evaluates the kernel lockdown file and
  passes only for `[integrity]` or `[confidentiality]`.
- `ELA_LINUX_AUDIT_CHECK_LSM_ENFORCING`: reads the active LSM list and verifies
  SELinux enforcing mode or AppArmor enabled mode.
- `ELA_LINUX_AUDIT_CHECK_MOUNT_ABSENT`: parses the mount table at `path`
  (normally `/proc/mounts`) and fails when a filesystem of the type named in
  `expected` is mounted. The debugfs and tracefs rules demonstrate the
  pattern.
- `ELA_LINUX_AUDIT_CHECK_DEVICE_MODE`: checks that the device at `path` has no
  group or other permission bits. An absent device is `not-applicable`.
- `ELA_LINUX_AUDIT_CHECK_CORE_PATTERN`: checks that core dumps are routed
  through a pipe/collector rather than written as unrestricted `core` files.

When adding a new check type, implement it in `run_special_rule()` and add a
unit test for pass, fail, and unavailable/unknown behavior. Keep probes
read-only and use `/proc`, `/sys`, and `stat(2)` directly; do not invoke shell
commands.

## Evidence and unknown state

Every rule must produce concise evidence. Missing interfaces, unavailable
kernel configuration, and permission errors become `unknown`, not `pass`.
Use `not-applicable` only when absence itself is the secure or expected state,
as with an absent `/dev/mem` device.

## Adding and testing a rule

1. Add the rule to `ela_linux_audit_rules[]`.
2. Keep the ID unique and update the catalog table in `docs/agent/linux/audit.md`.
3. Add evaluator tests to `tests/unit/agent/test_linux_audit_util.c`.
4. Add CLI coverage under `tests/agent/scripts/linux/` or
   `tests/agent/shell/linux/` when argument or exit-code behavior is involved.
5. Build and run `make build-unit-agent-c`, then execute
   `generated/agent_unit_tests`.

List the resulting catalog with:

```sh
./embedded_linux_audit linux audit --list-rules
```
