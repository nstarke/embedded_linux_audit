---
name: ela-collect
description: Run the baseline security evidence collection sweep on a connected ELA device via the client API — linux audit rules, U-Boot env/image scan, dmesg, netstat, kernel config, EFI vars, TPM state, filesystem checks — uploading everything to the server. Use when the user says "collect", "baseline", "sweep", or "audit <device>", or when a device has no artifacts yet.
---

# ELA collect — baseline evidence sweep on a live device

Prereq: the device must appear in `GET /terminal/sessions` (run `/ela-fleet`
first if unsure). Uses the client API preflight from the ela-fleet skill
(`ELA_CLIENT_URL`, `ELA_CLIENT_KEY`, bearer auth).

Two exec channels exist per device — pick the right one for each command:

- `POST /terminal/:mac/ela/exec` — body `{"command": "<ela agent command>"}`,
  sent **verbatim** to the ELA agent (e.g. `linux audit`, `uboot env`).
- `POST /terminal/:mac/linux/exec` — body `{"command": "<shell command>"}`,
  run through the agent's `linux execute-command`.

Both accept `timeoutMs` up to 60000. **Run commands one at a time per device**
— the agent REPL is serialized; concurrent commands to the same MAC fail.

Because the agent connected via the terminal server, its uploads
(`--output-http`) already flow to the agent helper API and become readable at
`GET /uploads/...` on the client API. Structured ELA commands (audit, uboot
env, efi dump-vars, tpm2, netstat, dmesg) auto-upload when the agent has
`ELA_API_URL` set; verify by watching upload counts grow between steps.

## Collection sequence

Run via `ela/exec` unless marked shell. After each step, note failures and
move on — a missing subsystem (no U-Boot, no EFI, no TPM) is a finding
("not applicable"), not an error to retry.

1. **Identity** (shell): `uname -a`, `cat /proc/cpuinfo | head -20`,
   `cat /etc/os-release 2>/dev/null; cat /etc/openwrt_release 2>/dev/null`
2. **Linux posture rules**: `linux audit all --quick` (aggregate: kernel,
   filesystem, persistence, identity, network, integrity, secrets, hardware).
   For a stricter pass on capable devices: `linux audit --profile hardened --no-fail`.
   These are long — if a step exceeds 60s, fall back to per-category runs
   (`linux audit filesystem --quick`, etc.) or spawn (below).
3. **Kernel ring buffer**: `linux dmesg`
4. **Network exposure**: `linux netstat`
5. **U-Boot** (skip on non-U-Boot targets): `uboot env`, `uboot image`,
   `uboot audit`
6. **EFI/UEFI** (x86/ARM server-class only): `efi dump-vars`, `efi orom`
7. **TPM** (if `/dev/tpm*` exists — check via shell first): `tpm2 getcap`,
   `tpm2 pcrread`, `tpm2 nvreadpublic`
8. **Module build facts** (enables later kmod builds): `linux modules buildinfo`
9. **Targeted shell checks** (via `linux/exec`, from `docs/manual-checklist.md`):
   - SUID/SGID: `find / -xdev -perm /6000 -type f 2>/dev/null`
   - World-writable in critical paths: `find /etc /bin /sbin /usr/bin /usr/sbin -perm -o+w -type f 2>/dev/null`
   - `cat /proc/mounts`
   - `cat /etc/passwd`; shadow perms: `ls -l /etc/shadow`
   - SSH config: `cat /etc/ssh/sshd_config 2>/dev/null | grep -Ei 'permitrootlogin|passwordauthentication'`
   - Key sysctls: `for f in dmesg_restrict kptr_restrict modules_disabled sysrq; do echo -n "$f="; cat /proc/sys/kernel/$f 2>/dev/null || echo '?'; done`

## Long-running collection (spawn)

For anything over 60s (full-filesystem find, pcap, `linux remote-copy`), use
spawn instead of exec:

```sh
# Linux background process (tracked; killable via DELETE /terminal/:mac/spawn/:pid)
curl -s -X POST -H "Authorization: Bearer $ELA_CLIENT_KEY" -H 'Content-Type: application/json' \
  -d '{"command":"find","args":["/","-xdev","-perm","/6000","-type","f"]}' \
  "$ELA_CLIENT_URL/terminal/$MAC/linux/spawn"

# Self-daemonizing ELA command (untracked)
curl -s -X POST -H "Authorization: Bearer $ELA_CLIENT_KEY" -H 'Content-Type: application/json' \
  -d '{"command":"linux pcap --interface eth0"}' \
  "$ELA_CLIENT_URL/terminal/$MAC/ela/spawn"
```

While a spawned ELA command occupies the agent shell, further exec calls to
that device will 504 — plan the order so spawns come last, or wait.

Only capture pcap when the user has confirmed engagement scope permits it.

## Verify and report

After the sweep, confirm evidence landed:

```sh
curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" "$ELA_CLIENT_URL/uploads"
```

Report: which steps ran, which were not applicable and why, which uploads
appeared (type + count deltas), and any commands that failed with their
output. Then recommend `/ela-triage` to analyze the collected data.
