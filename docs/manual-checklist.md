# Embedded Linux Security Assessment — Manual Checklist

This checklist is intended to guide a manual security assessment of an embedded Linux device using `embedded_linux_audit` (`ela`). Work through the sections in order; check off each item as it is completed or confirmed not applicable.

---

## Setup

- [ ] Confirm target architecture and obtain the matching static binary from the release page
- [ ] Transfer the binary to the target device (`linux remote-copy`, SCP, TFTP, or serial)
- [ ] Verify the binary executes (`./ela` with no arguments should open the interactive shell)
- [ ] (Optional) Start the agent helper API on the assessment workstation and configure `ELA_API_URL` to collect data centrally
- [ ] (Optional) Start the WebSocket terminal server and connect the agent with `transfer --remote ws://...` for a persistent interactive session

---

## U-Boot

### Environment

- [ ] Scan for U-Boot environments across MTD/UBI/block devices
  ```
  uboot env --scan
  ```
- [ ] Identify active environment partition(s) and note redundancy configuration
- [ ] Check whether the environment is stored in a writable, unprotected region
- [ ] Review all environment variables for security-relevant settings:
  - `bootcmd` — confirm it does not load from untrusted sources (USB, TFTP with no authentication)
  - `bootargs` — check for `init=`, `rdinit=`, or kernel command-line injection opportunities
  - `serverip` / `ipaddr` — note any hardcoded network targets
  - `bootdelay` — confirm it is not set to `-2` (which bypasses the countdown prompt entirely)
  - Any variable that controls Secure Boot, FIT verification, or signature checking
- [ ] Export the full environment for offline analysis
  ```
  uboot env --output-format json --output-http http://<workstation>/upload
  ```

### Images

- [ ] Scan for U-Boot images on flash and block devices
  ```
  uboot image --scan
  ```
- [ ] Record load address, entry point, and image type for each detected image
- [ ] Check whether FIT images are present and whether they require verified signatures
- [ ] Extract any images of interest for offline analysis

### Security audit

- [ ] Run the compiled audit ruleset against the active environment
  ```
  uboot audit
  ```
- [ ] Review and document findings for each rule:
  - Secure Boot enabled and enforced
  - Environment write-protection active
  - Command-line initialization variables not user-writable
  - No unsigned FIT image loading permitted

---

## Linux kernel

### Kernel configuration and boot

- [ ] Capture the kernel ring buffer and review for security-relevant messages
  ```
  linux dmesg
  ```
- [ ] Look for: kernel version, LSM (SELinux/AppArmor/SMACK) status, lockdown mode, IOMMU activity, secure boot enforcement messages, error/warning messages at boot
- [ ] Check whether `/proc/config.gz` or `/boot/config-*` is accessible; if so, retrieve and review key options:
  - `CONFIG_SECURITY_*` — LSM configuration
  - `CONFIG_MODULE_SIG` / `CONFIG_MODULE_SIG_FORCE` — module signature enforcement
  - `CONFIG_DEVMEM` / `CONFIG_STRICT_DEVMEM` — `/dev/mem` restrictions
  - `CONFIG_KEXEC` — kexec support (potential bypass for Secure Boot)
  - `CONFIG_RANDOMIZE_BASE` — KASLR
  - `CONFIG_DEBUG_*` — debug interfaces that should be disabled in production

### Filesystem and file permissions

- [ ] Enumerate world-writable files and directories in critical paths
  ```
  linux execute-command "find /etc /bin /sbin /usr/bin /usr/sbin -perm -o+w -type f 2>/dev/null"
  ```
- [ ] Check for SUID/SGID binaries
  ```
  linux execute-command "find / -perm /6000 -type f 2>/dev/null"
  ```
- [ ] List files under `/etc/` to identify configuration exposure
  ```
  linux list-files /etc --recursive
  ```
- [ ] Check for sensitive files with overly permissive read access:
  - `/etc/shadow` — should be mode 640 or tighter
  - `/etc/passwd` — should not contain non-system users with UID 0
  - `/etc/sudoers` and `/etc/sudoers.d/`
  - Private keys in `/etc/`, `/root/`, or service home directories
- [ ] Review `/proc/mounts` or `mount` output for security-relevant mount options (noexec, nosuid, nodev)
  ```
  linux execute-command "cat /proc/mounts"
  ```
- [ ] Check whether root filesystem is mounted read-only in production
- [ ] Review `/etc/fstab` if present

### Running processes and services

- [ ] Enumerate running processes and listening network services
  ```
  linux execute-command "ps aux"
  linux execute-command "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"
  ```
- [ ] Identify any services running as root that do not need to
- [ ] Check for debug or development services (telnetd, ftpd, gdbserver, dropbear with root login enabled)
- [ ] Identify services exposed on the network; assess whether they are expected for a production device

### Users and credentials

- [ ] Review `/etc/passwd` for unexpected accounts, shells, or UID 0 entries
- [ ] Review `/etc/shadow` for accounts with empty or weak password hashes
- [ ] Check for hardcoded credentials in common locations:
  - `/etc/` configuration files
  - Init scripts under `/etc/init.d/`, `/etc/rc.d/`, or systemd unit files
  - `/usr/share/`, `/var/`, or application-specific directories
- [ ] Check SSH configuration (`/etc/ssh/sshd_config`):
  - `PermitRootLogin` — should be `no` or `prohibit-password`
  - `PasswordAuthentication` — should be `no` in production
  - `AuthorizedKeysFile` — confirm expected paths; check for unexpected keys

### Kernel interfaces

- [ ] Review `/proc/sys/kernel/` for dangerous settings
  ```
  linux execute-command "sysctl -a 2>/dev/null | grep -E 'kernel\\.(dmesg_restrict|kptr_restrict|perf_event_paranoid|randomize_va_space|modules_disabled|sysrq)'"
  ```
- [ ] Check `/proc/sys/kernel/dmesg_restrict` (should be 1)
- [ ] Check `/proc/sys/kernel/kptr_restrict` (should be 2)
- [ ] Check `/dev/mem` and `/dev/kmem` permissions
- [ ] Check whether `/proc/kcore` is accessible
- [ ] Verify kernel modules: list loaded modules and check signing policy
  ```
  linux execute-command "lsmod"
  linux execute-command "cat /proc/sys/kernel/modules_disabled 2>/dev/null"
  ```

---

## EFI / UEFI (if applicable)

- [ ] Dump all EFI variables
  ```
  efi dump-vars --output-format json --output-http http://<workstation>/upload
  ```
- [ ] Review Secure Boot state variables:
  - `SecureBoot` (8be4df61-93ca-11d2-aa0d-00e098032b8c) — value `01` = enabled
  - `SetupMode` — value `00` = Secure Boot in user mode (enrolled keys, enforcement active)
  - `AuditMode` / `DeployedMode` — note states
- [ ] Review enrolled keys: `PK`, `KEK`, `db`, `dbx`
  - Confirm `PK` is set (no platform key = Secure Boot not enforced)
  - Check `db` for unexpected certificates
  - Check `dbx` is populated (revocation list)
- [ ] Note any vendor-specific or debug EFI variables that suggest test/development firmware
- [ ] List EFI option ROMs and extract any of interest
  ```
  efi orom
  ```

---

## BIOS / Legacy firmware (if applicable)

- [ ] List and extract PCI option ROMs
  ```
  bios orom
  ```
- [ ] Transfer extracted option ROMs to workstation for offline analysis

---

## TPM 2.0 (if applicable)

- [ ] Query TPM capabilities and properties
  ```
  tpm2 getcap properties-fixed
  tpm2 getcap properties-variable
  ```
- [ ] Read PCR values for relevant registers (PCR 0–7 for boot measurement)
  ```
  tpm2 pcrread sha256:0,1,2,3,4,5,6,7
  ```
- [ ] Check NV index inventory for unexpected or sensitive data stores
  ```
  tpm2 nvreadpublic
  ```
- [ ] Confirm expected PCR values match known-good reference measurements
- [ ] Assess whether TPM measurements are being used for remote attestation or sealing disk encryption keys

---

## Network and remote access

- [ ] Enumerate network interfaces and addresses
  ```
  linux execute-command "ip addr 2>/dev/null || ifconfig 2>/dev/null"
  ```
- [ ] Review routing table and firewall rules
  ```
  linux execute-command "ip route; ip6route 2>/dev/null"
  linux execute-command "iptables -L -n -v 2>/dev/null; ip6tables -L -n -v 2>/dev/null"
  ```
- [ ] Confirm no unexpected outbound connections are established at boot
- [ ] Assess whether any remote management interface (SSH, HTTP API, MQTT, SNMP) is accessible from untrusted network segments
- [ ] Check TLS certificate validity and cipher configuration for any exposed HTTPS services

---

## Symlinks

- [ ] Enumerate symlinks under key directories and check for dangerous targets
  ```
  linux list-symlinks /etc --recursive
  linux list-symlinks /tmp --recursive
  linux list-symlinks /var --recursive
  ```
- [ ] Identify any symlinks pointing outside their expected directory tree (potential path traversal or privilege escalation)

---

## Data collection and reporting

- [ ] Confirm all collected data has been uploaded to or retrieved by the assessment workstation
- [ ] Archive the raw data under a timestamped directory for the engagement record
- [ ] Document the firmware version, device model, and hardware revision
- [ ] Document the kernel version (`uname -a`) and build date
- [ ] Record findings against each section above with severity ratings
- [ ] Produce a final report with remediation recommendations

---

## Quick-start one-liner

Run all collection steps non-interactively via a remote script served by the helper API:

```sh
./ela --api-key <token> --output-http http://<workstation>:5000/<mac>/upload/cmd \
     --script http://<workstation>:5000/scripts/full-audit.ela
```

Or download and run the agent test suite directly on the device:

```sh
curl -fsSL http://<workstation>:5000/tests/agent/shell/download_tests.sh | \
    sh -s -- --webserver http://<workstation>:5000 --auto-start
```
