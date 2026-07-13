# `embedded_linux_audit bios orom` Command

BIOS option ROM utilities for listing and pulling payloads from PCI sysfs ROM nodes.

When PCI sysfs ROM attributes are absent or unreadable, use the kernel-backed
top-level [`orom list` and `orom dump`](../kernel-hardware.md#pci-option-roms)
commands instead.

## `bios orom` subcommands

- `pull` — send matching BIOS option ROM payload bytes to remote output
- `list` — enumerate matching BIOS option ROM candidates and emit formatted records

## `bios orom` arguments

- verbose logging is enabled by default; use top-level `--quiet` to suppress progress and mirrored verbose messages
- `--output-tcp <IPv4:port>` — send each ROM over TCP; preferred at the top level
- `--output-http <http://host:port/path>` — send each ROM via HTTP POST; preferred at the top level
- `--output-http <https://host:port/path>` — send each ROM via HTTPS POST; preferred at the top level
- `--insecure` — top-level global option to disable TLS certificate/hostname verification for HTTPS output

## Constraints

- exactly one transport output is required: `--output-tcp` or `--output-http`
- `--output-http` accepts both `http://` and `https://` URLs
- `bios orom` filters sysfs ROM images for legacy payloads; it is separate
  from the unfiltered, kernel-mapped top-level `orom` command

## Examples

```bash
./embedded_linux_audit --output-tcp 192.168.1.50:5000 bios orom pull
./embedded_linux_audit --output-http http://192.168.1.50:5000/orom bios orom pull
./embedded_linux_audit --insecure --output-http https://192.168.1.50:5443/orom bios orom pull
./embedded_linux_audit --output-format json --output-http http://192.168.1.50:5000/orom bios orom list
```
