# Agent Documentation

This section contains documentation for the `embedded_linux_audit` agent, organized by features, shared reference material, and command group/subcommand hierarchy.

## Getting Started

- [Getting Started Index](getting-started/index.md)
- [Build and Release Notes](getting-started/build.md)

## Features

- [Features Index](features/index.md)
- [Interactive Mode](features/interactive-mode.md)
- [Output Formats and Remote Output](features/output-formats-and-remote-output.md)
- [`embedded_linux_audit --script` Feature](features/script-feature.md)

## Command Groups

### Arch

- [`embedded_linux_audit arch`](arch/index.md)

### U-Boot

- [U-Boot Index](uboot/index.md)
- [`embedded_linux_audit uboot env`](uboot/env.md)
- [`embedded_linux_audit uboot image`](uboot/image.md)
- [`embedded_linux_audit uboot audit`](uboot/audit.md)
- [Audit Rules Reference](uboot/audit-rules.md)

### Linux

- [Linux Index](linux/index.md)
- [`embedded_linux_audit linux dmesg`](linux/dmesg.md)
- [`embedded_linux_audit linux download-file`](linux/download-file.md)
- [`embedded_linux_audit linux execute-command`](linux/execute-command.md)
- [`embedded_linux_audit linux grep`](linux/grep.md)
- [`embedded_linux_audit linux list-files`](linux/list-files.md)
- [`embedded_linux_audit linux list-symlinks`](linux/list-symlinks.md)
- [`embedded_linux_audit linux remote-copy`](linux/remote-copy.md)

### TPM2

- [`embedded_linux_audit tpm2`](tpm2/index.md)

### EFI

- [`embedded_linux_audit efi`](efi/index.md)
- [`embedded_linux_audit efi dump-vars`](efi/dump-vars.md)

### BIOS

- [BIOS Index](bios/index.md)
- [`embedded_linux_audit bios orom`](bios/orom.md)

## Reference

- [Reference Index](reference/index.md)
- [Tests](reference/tests.md)
- [Notes and Cautions](reference/notes-and-cautions.md)