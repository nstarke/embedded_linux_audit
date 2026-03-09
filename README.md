# uboot_audit

`uboot_audit` is a Linux host-side C utility for U-Boot discovery and validation workflows on embedded systems. It focuses on three tasks:

- **Environment discovery** (`uboot_audit uboot env`): scans flash/block devices for valid U-Boot environment candidates and can emit `fw_env.config` entries.
- **Image discovery/extraction** (`uboot_audit uboot image`): scans for likely U-Boot image headers, resolves load addresses, and can pull image bytes.
- **Rule-based auditing** (`uboot_audit uboot audit`): runs compiled rules against selected bytes to validate security and configuration expectations.
- **Linux utilities** (`uboot_audit linux dmesg`, `uboot_audit linux remote-copy`): collect kernel logs and transfer files.

## How it works

At runtime, `uboot_audit` probes MTD/UBI and block devices (including SD/eMMC patterns), applies U-Boot-aware parsers/validators (CRC, FIT/uImage structure checks, rule engines), and produces human-readable or machine-readable output (`txt`, `csv`, `json`).

This makes it useful for field diagnostics, incident response, and recovery validation where you need a single tool to identify environments/images and assess boot-policy risk.

## Portable static GitHub release builds

GitHub Releases are produced by a cross-build workflow (`.github/workflows/release-cross-static.yml`) that compiles **fully static** binaries across many architectures using **Zig + musl** targets. Release artifacts are uploaded as per-architecture `uboot_audit-*` binaries.

Why this matters:

- No target-side dependency installation required for common use cases.
- Better portability across minimal/older Linux environments.
- Easier drop-in usage for triage and recovery workflows.

## Documentation

The full usage and reference material has moved to the `docs/` folder:

- [Documentation index](docs/index.md)