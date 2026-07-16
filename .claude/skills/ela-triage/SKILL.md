---
name: ela-triage
description: Read back and analyze collected ELA artifacts through the client API uploads routes — grade linux-audit findings, review U-Boot environment and Secure Boot posture, EFI variables, TPM PCRs, netstat exposure, dmesg, and fuzz results — producing a prioritized findings list. Use after /ela-collect, or whenever the user asks "what did we find", "analyze the uploads", or "triage <device>".
---

# ELA triage — analyze collected artifacts into findings

Pure read-back: this skill only uses `GET /uploads...` on the client API and
never touches the device. Safe to run any time. Uses the standard preflight
(`ELA_CLIENT_URL`, `ELA_CLIENT_KEY`, bearer auth — see ela-fleet).

## Fetch pattern

```sh
# inventory
curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" "$ELA_CLIENT_URL/uploads"
# metadata list for one type (newest first; ?limit up to 1000, ?offset)
curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" "$ELA_CLIENT_URL/uploads/linux-audit?limit=50"
# full record with parsed payloadText/payloadJson
curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" "$ELA_CLIENT_URL/uploads/linux-audit/42"
# original bytes (for binaries: orom, uboot-image, coredump, pcap, physmem)
curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" -o /tmp/artifact.bin \
  "$ELA_CLIENT_URL/uploads/orom/7/raw"
```

Filter by device using the `macAddress` metadata field. When multiple records
of a type exist for a device, triage the **newest** and note if older ones
show drift (e.g. a rule that used to pass now fails).

Valid types (from `api/lib/uploadTypes.js`): arch, cmd, coredump, dmesg,
efi-vars, file, file-list, grep, kernel-config, linux-audit, log, logs,
module-buildinfo, module-vermagic, netstat, orom, pcap, physmem, symlink-list,
tpm2-createprimary, tpm2-getcap, tpm2-nvreadpublic, tpm2-pcrread, uboot-image,
uboot-environment, wlan-fuzz, eth-fuzz, bt-fuzz, cpu-fuzz.

## Triage checklist per artifact type

**linux-audit** — findings carry stable rule IDs, status
(pass/fail/unknown/not-applicable), severity, evidence, remediation. Group
failures by severity; treat `unknown` as "verify manually", never as pass.

**uboot-environment / uboot-image** — per `docs/manual-checklist.md`:
`bootcmd` loading from USB/TFTP without authentication; `bootargs` with
`init=`/`rdinit=` injection surface; `bootdelay=-2` note (bypasses prompt);
signature/FIT-verification variables; env stored writable/unprotected.

**efi-vars** — `SecureBoot` (01 = enabled), `SetupMode` (00 = enforcing),
missing `PK` (= not enforced), unexpected `db` certs, empty `dbx`, debug or
vendor test variables.

**tpm2-pcrread / tpm2-getcap / tpm2-nvreadpublic** — all-zero PCRs 0–7 mean
no measured boot; note NV indexes that could store secrets.

**netstat** — services listening on 0.0.0.0/:: vs loopback; debug daemons
(telnet 23, gdbserver, adb 5555); anything running as root that need not.

**dmesg** — kernel version and taint, LSM/lockdown lines, oops/BUG/WARN
traces, secure-boot enforcement messages, firmware load errors.

**kernel-config** — CONFIG_MODULE_SIG(_FORCE), CONFIG_STRICT_DEVMEM,
CONFIG_KEXEC, CONFIG_RANDOMIZE_BASE, CONFIG_DEBUG_*, CONFIG_SECURITY_*.

**cmd / file / grep / file-list / symlink-list** — output of shell checks:
SUID inventory, world-writable files, shadow perms, sshd_config, symlinks
escaping their tree; credentials or private keys in configs.

**wlan-fuzz / eth-fuzz / bt-fuzz / cpu-fuzz** — crash/anomaly records; each
reproducible crash is a finding (see /ela-fuzz for follow-up). **coredump** —
correlate with fuzz runs or watched processes; a core from a network-facing
daemon is high priority.

## Output

Produce a findings report, most severe first. Each finding: severity
(critical/high/medium/low/info), affected device (MAC + alias), evidence
(artifact type + record id so it's re-fetchable), impact in one sentence,
remediation. End with the not-applicable/unknown list and gaps in collection
(types with zero records that should exist for this device class) —
recommend `/ela-collect` steps to fill them, `/ela-deep-dive` for binaries
worth reversing, or `/ela-fuzz` for interfaces worth fuzzing.

Findings live only in your report — the server stores evidence, not
conclusions. Offer to write the report to a file for the engagement record.
