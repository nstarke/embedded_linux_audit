# `uboot_audit linux remote-copy` Command

Copies a local file to a remote destination using one of:

- TCP (`--output-tcp`)
- HTTP POST (`--output-http`)
- HTTPS POST (`--output-https`)

The source path must be a full absolute OS path and must point to a regular file.

## `remote-copy` arguments

- `<absolute-file-path>` — required source file path (must start with `/`)
- `--output-tcp <IPv4:port>` — send file bytes over TCP
- `--output-http <http://host:port/path>` — send file bytes in HTTP POST body
- `--output-https <https://host:port/path>` — send file bytes in HTTPS POST body
- `--insecure` — disable TLS certificate and hostname verification for HTTPS output
- `--verbose` — print transfer progress

## Constraints

- Exactly one remote output target is required:
  - `--output-tcp` **or** `--output-http` **or** `--output-https`
- `--output-http` and `--output-https` are mutually exclusive
- `--output-format` does not affect this subcommand; transfers are raw file bytes

## Examples

```bash
./uboot_audit linux remote-copy /tmp/fw.bin --output-tcp 192.168.1.50:5000
./uboot_audit linux remote-copy /tmp/fw.bin --output-http http://192.168.1.50:5000/upload
./uboot_audit linux remote-copy /tmp/fw.bin --output-https https://192.168.1.50:5443/upload
./uboot_audit linux remote-copy /tmp/fw.bin --output-https https://192.168.1.50:5443/upload --insecure --verbose
```
