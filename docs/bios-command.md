# `embedded_linux_audit bios orom` Command

BIOS option ROM utilities for listing and pulling payloads from PCI sysfs ROM nodes.

## `bios orom` subcommands

- `pull` — send matching BIOS option ROM payload bytes to remote output
- `list` — enumerate matching BIOS option ROM candidates and emit formatted records

## `bios orom` arguments

- `--verbose` — print progress and mirror verbose messages to configured network output; preferred at the top level
- `--output-tcp <IPv4:port>` — send each ROM over TCP; preferred at the top level
- `--output-http <http://host:port/path>` — send each ROM via HTTP POST; preferred at the top level
- `--output-https <https://host:port/path>` — send each ROM via HTTPS POST; preferred at the top level
- `--insecure` — disable TLS certificate/hostname verification for HTTPS output

## Constraints

- exactly one transport output is required: `--output-tcp`, `--output-http`, or `--output-https`
- use only one of `--output-http` and `--output-https`

## Examples

```bash
./embedded_linux_audit --output-tcp 192.168.1.50:5000 --verbose bios orom pull
./embedded_linux_audit --output-http http://192.168.1.50:5000/orom --verbose bios orom pull
./embedded_linux_audit --output-https https://192.168.1.50:5443/orom --verbose bios orom pull --insecure
./embedded_linux_audit --output-format json --output-http http://192.168.1.50:5000/orom --verbose bios orom list
```
