# `embedded_linux_audit linux audit`

`linux audit` runs compiled security posture rules directly against Linux
kernel interfaces. It does not invoke a shell or require `sysctl`, making it
suitable for minimal BusyBox and embedded targets.

## Usage

```text
embedded_linux_audit linux audit [--profile embedded|hardened]
                                  [--rule <id>] [--list-rules]
                                  [--root <path>] [--no-fail]
```

The default `embedded` profile checks controls expected to be broadly usable
on production embedded devices. The `hardened` profile includes those checks,
uses stricter thresholds where appropriate, and adds performance-event, Yama
ptrace, and unprivileged-BPF restrictions.

Each finding contains a stable rule ID, status, severity, category, evidence,
and remediation. The possible statuses are `pass`, `fail`, `unknown`, and
`not-applicable`. A missing or unreadable kernel interface is reported as
`unknown`; it is never treated as a pass.

By default, the command exits with status 1 when any rule fails, 2 for invalid
arguments, and 0 otherwise. `--no-fail` makes completed assessments return 0
even when findings fail, which is useful in collection scripts. Operational
errors still return nonzero.

## Examples

```sh
# Run the portable embedded profile
./embedded_linux_audit linux audit

# Run the stricter policy and emit newline-delimited JSON
./embedded_linux_audit --output-format json linux audit --profile hardened

# Inspect the compiled rule catalog
./embedded_linux_audit linux audit --list-rules

# Run a single rule
./embedded_linux_audit linux audit --profile hardened --rule ELA-LINUX-008

# Audit a mounted or extracted root filesystem
./embedded_linux_audit linux audit --root /mnt/firmware-root --no-fail
```

`--root` prepends an alternate absolute root to probe paths. Kernel sysctls
must be represented beneath that tree (for example,
`/mnt/target/proc/sys/kernel/randomize_va_space`). This is useful with a mounted
target namespace or a captured procfs tree; an ordinary offline rootfs usually
does not contain runtime sysctl values and will therefore produce `unknown`.

For contributors adding controls, see the [audit engine rule format](audit-engine.md).

## Filesystem and permissions audit

## Aggregate audit

```text
embedded_linux_audit linux audit all [--quick] [--root <absolute-path>]
```

Runs the kernel, filesystem, persistence, identity, network, integrity,
secrets, and hardware audits sequentially. `--root` is passed to every
category; `--quick` is passed to scanners that support bounded traversal.
Each category emits its normal structured records and the aggregate returns
the highest exit status reported by any category.

The filesystem scanner is available as a nested command:

```text
embedded_linux_audit linux audit filesystem [--quick] [--root <absolute-path>]
```

It checks temporary-file-system mount flags, writable executable locations,
SUID/SGID files, file capabilities, device-node permissions, sensitive-file
permissions, writable init scripts, and symlinks that leave trusted directory
trees. `--root` audits an extracted or mounted target tree; runtime mount data
is read from `<root>/proc/mounts`. `--quick` limits recursion and skips broader
trees such as `/opt`, `/usr/local/bin`, and systemd/init locations that are
expensive on a full host. Findings use the same text/CSV/NDJSON formats and
`linux-audit` upload type as the kernel rules.

Filesystem rule IDs are stable and intended for automation:

| Rule | Control |
|---|---|
| `ELA-FS-001` | Writable executable path or directory |
| `ELA-FS-002` | SUID/SGID file |
| `ELA-FS-003` | File capability |
| `ELA-FS-004` | Sensitive-file permissions |
| `ELA-FS-005` | Unsafe temporary mount options |
| `ELA-FS-006` | Writable init script/unit |
| `ELA-FS-007` | Insecure device node permissions |
| `ELA-FS-008` | Symlink escaping a trusted tree |
| `ELA-FS-900` | Scanner could not inspect a path |

## Persistence and service discovery

```text
embedded_linux_audit linux audit persistence [--quick] [--root <absolute-path>]
```

This command enumerates systemd units, SysV/OpenRC scripts, cron jobs,
`inittab`, shell profiles, udev rules, module-load/modprobe configuration, and
common vendor startup directories. It reports writable persistence files and
startup entries that invoke transient or externally sourced locations such as
`/tmp`, `/home`, or HTTP(S) URLs. `--quick` limits recursive directory depth;
normal mode checks all files in the listed persistence trees. Findings use the
same structured output and `linux-audit` upload conventions.

| Rule | Control |
|---|---|
| `ELA-PERSIST-001` | Writable systemd unit |
| `ELA-PERSIST-002` | Writable SysV/OpenRC script |
| `ELA-PERSIST-003` | Writable cron job |
| `ELA-PERSIST-004` | Writable shell profile |
| `ELA-PERSIST-005` | Writable udev rule |
| `ELA-PERSIST-006` | Writable module autoload configuration |
| `ELA-PERSIST-007` | Writable/vendor startup mechanism |
| `ELA-PERSIST-008` | Externally sourced or transient executable |
| `ELA-PERSIST-900` | Persistence path could not be inspected |

## Identity and credential posture

```text
embedded_linux_audit linux audit identity [--quick] [--root <absolute-path>]
```

The identity audit parses passwd/shadow data without emitting password hashes,
detects empty passwords and duplicate UID 0 accounts, identifies interactive
service accounts, checks stale `authorized_keys`, SSH and sudo policy, and
validates private-key permissions. `--quick` skips age-based authorized-key
checks. Evidence names accounts and paths but never includes credential
hashes or private-key contents.

| Rule | Control |
|---|---|
| `ELA-ID-001` | Empty password |
| `ELA-ID-002` | Duplicate UID 0 account |
| `ELA-ID-003` | Interactive service account |
| `ELA-ID-004` | Stale authorized key |
| `ELA-ID-005` | Unsafe SSH setting |
| `ELA-ID-006` | Permissive sudo rule |
| `ELA-ID-007` | Private-key permissions |
| `ELA-ID-008` | Permissive identity-file permissions |
| `ELA-ID-900` | Identity data could not be inspected |

## Network exposure audit

```text
embedded_linux_audit linux audit network [--root <absolute-path>]
```

Combines interface, route, socket, namespace, DNS, and firewall probes into a
single report. Socket inspection covers the IPv4 and IPv6 TCP and UDP tables
(`/proc/net/tcp`, `tcp6`, `udp`, and `udp6`); it highlights wildcard
listeners, clear-text service ports (including UDP services such as TFTP,
SNMP, syslog, and SSDP), missing firewall policy, and established outbound
TCP connections. Findings use the standard structured output formats and are
intentionally conservative when process ownership or runtime procfs data is
unavailable. An absent IPv6 or UDP table is skipped silently; an unreadable
one is reported as `unknown`.

| Rule | Control |
|---|---|
| `ELA-NET-001` | Wildcard listener |
| `ELA-NET-002` | Clear-text network service |
| `ELA-NET-003` | Missing firewall policy |
| `ELA-NET-004` | Missing DNS configuration |
| `ELA-NET-005` | Unexpected outbound connection |
| `ELA-NET-900` | Network data could not be inspected |

## Integrity and measured boot

```text
embedded_linux_audit linux audit integrity [--root <absolute-path>]
```

Checks IMA/EVM policy state, fs-verity availability, dm-verity/dm-crypt
mounts, kernel keyring visibility, TPM event-log presence, and TPM device
availability. PCR replay is reported explicitly as unknown until the event log
can be replayed using the target's hash banks and compared with live TPM PCRs;
raw PCR presence is never treated as successful verification.

| Rule | Control |
|---|---|
| `ELA-INT-001` | IMA measurement policy |
| `ELA-INT-002` | IMA appraisal policy |
| `ELA-INT-003` | fs-verity availability |
| `ELA-INT-004` | dm-verity/dm-crypt mappings |
| `ELA-INT-006` | Kernel keyring visibility |
| `ELA-INT-007` | TPM event log |
| `ELA-INT-008` | TPM PCR replay/live comparison |

## Secret discovery

```text
embedded_linux_audit linux audit secrets [--quick] [--collect] [--root <absolute-path>]
```

The scanner searches common configuration, home, firmware, and local-data
trees for API keys, private keys, embedded/default credentials, tokens, and
high-entropy strings. Findings include only file locations and FNV-64
fingerprints by default; detected content is replaced with `[redacted]`.
`--collect` explicitly authorizes including matched content in the output and
should only be used with protected output destinations.

| Rule | Control |
|---|---|
| `ELA-SEC-001` | API key or token |
| `ELA-SEC-002` | Private key material |
| `ELA-SEC-003` | Default or embedded credential |
| `ELA-SEC-004` | High-entropy string |
| `ELA-SEC-900` | Secret path could not be inspected |

## Hardware/debug attack-surface inventory

```text
embedded_linux_audit linux audit hardware [--root <absolute-path>]
```

Inventories exposed GPIO, I²C, SPI, UART, debugfs, tracefs, JTAG, watchdog,
DMA, USB gadget, and firmware interfaces through sysfs/devfs. Writable
firmware controls are reported as high-severity findings; unavailable runtime
interfaces are explicit `unknown` results.

| Rule | Control |
|---|---|
| `ELA-HW-001`–`ELA-HW-010` | Exposed embedded hardware/debug interfaces |
| `ELA-HW-011` | Writable firmware interface |
| `ELA-HW-900` | Hardware interface could not be inspected |

## Output and upload

The command honors global `--output-format txt|csv|json`. JSON output is
newline-delimited JSON: one object per finding followed by a summary object.
CSV output includes a header and a summary row.

Global `--output-tcp` streams the same payload. Global `--output-http` uploads
it using the `linux-audit` upload type.

## Initial rule catalog

| Rule | Control | Profiles |
|---|---|---|
| `ELA-LINUX-001` | Address-space randomization | embedded, hardened |
| `ELA-LINUX-002` | Kernel pointer restriction | embedded, hardened |
| `ELA-LINUX-003` | Kernel log restriction | embedded, hardened |
| `ELA-LINUX-004` | Protected hardlinks | embedded, hardened |
| `ELA-LINUX-005` | Protected symlinks | embedded, hardened |
| `ELA-LINUX-006` | Performance event restriction | hardened |
| `ELA-LINUX-007` | Yama ptrace restriction | hardened |
| `ELA-LINUX-008` | Unprivileged BPF restriction | hardened |
| `ELA-LINUX-009` | KASLR boot override detection | embedded, hardened |
| `ELA-LINUX-010` | Forced kernel module signatures | hardened |
| `ELA-LINUX-011` | Kernel lockdown | hardened |
| `ELA-LINUX-012` | Enforcing Linux security module | hardened |
| `ELA-LINUX-013` | Kexec load restriction | hardened |
| `ELA-LINUX-014` | User namespace restriction | hardened |
| `ELA-LINUX-015` | Debugfs not exposed | hardened |
| `ELA-LINUX-016` | Magic SysRq disabled | hardened |
| `ELA-LINUX-017` | Restricted `/dev/mem` | hardened |
| `ELA-LINUX-018` | Controlled core dumps | hardened |
| `ELA-LINUX-019` | Kexec disabled in kernel | hardened |
| `ELA-LINUX-020` | Protected FIFOs | embedded, hardened |
| `ELA-LINUX-021` | Protected regular files | embedded, hardened |
| `ELA-LINUX-022` | SUID core dumps disabled | embedded, hardened |
| `ELA-LINUX-023` | Module loading locked | hardened |
| `ELA-LINUX-024` | Minimum mmap address | embedded, hardened |
| `ELA-LINUX-025` | Unprivileged userfaultfd disabled | hardened |
| `ELA-LINUX-026` | TTY line-discipline autoload disabled | hardened |
| `ELA-LINUX-027` | io_uring restriction | hardened |
| `ELA-LINUX-028` | IP forwarding disabled | hardened |
| `ELA-LINUX-029` | ICMP redirects not accepted | embedded, hardened |
| `ELA-LINUX-030` | ICMP redirects not sent | embedded, hardened |
| `ELA-LINUX-031` | Source-routed packets rejected | embedded, hardened |
| `ELA-LINUX-032` | Reverse-path filtering | embedded, hardened |
| `ELA-LINUX-033` | TCP SYN cookies | embedded, hardened |
| `ELA-LINUX-034` | CPU mitigations boot override | embedded, hardened |
| `ELA-LINUX-035` | SMEP boot override | embedded, hardened |
| `ELA-LINUX-036` | SMAP boot override | embedded, hardened |
| `ELA-LINUX-037` | Page-table isolation boot override | embedded, hardened |
| `ELA-LINUX-038` | Init shell boot override | embedded, hardened |
| `ELA-LINUX-039` | Initramfs shell boot override | embedded, hardened |
| `ELA-LINUX-040` | SELinux boot override | embedded, hardened |
| `ELA-LINUX-041` | AppArmor boot override | embedded, hardened |
| `ELA-LINUX-042` | LSM enforcing boot override | embedded, hardened |
| `ELA-LINUX-043` | Module signature boot override | embedded, hardened |
| `ELA-LINUX-044` | Strict kernel memory permissions | hardened |
| `ELA-LINUX-045` | Strong kernel stack protector | hardened |
| `ELA-LINUX-046` | Hardened usercopy | hardened |
| `ELA-LINUX-047` | Fortified kernel string functions | hardened |
| `ELA-LINUX-048` | Strict `/dev/mem` access | hardened |
| `ELA-LINUX-049` | Debugfs compiled out | hardened |
| `ELA-LINUX-050` | Hardened SLAB freelists | hardened |
| `ELA-LINUX-051` | Zero-initialized allocations | hardened |
| `ELA-LINUX-052` | Seccomp support | hardened |
| `ELA-LINUX-053` | Tracefs not exposed | hardened |
