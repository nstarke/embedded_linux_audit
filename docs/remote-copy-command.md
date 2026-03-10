# `embedded_linux_audit linux remote-copy` Command

Copies a local file, device-like path, proc/sysfs path, or directory contents to a remote destination using one of:

- TCP (`--output-tcp`, preferably passed as a top-level `embedded_linux_audit` option)
- HTTP POST (`--output-http`, preferably passed as a top-level option)
- HTTPS POST (`--output-https`, preferably passed as a top-level option)

The source path must be a full absolute OS path. Directory uploads are supported only with HTTP(S).

## `remote-copy` arguments

- `<absolute-path>` — required source path (must start with `/`)
- `--output-tcp <IPv4:port>` — send file bytes over TCP; preferred at the top level
- `--output-http <http://host:port/path>` — send file bytes in HTTP POST body; preferred at the top level
- `--output-https <https://host:port/path>` — send file bytes in HTTPS POST body; preferred at the top level
- `--recursive` — recurse into subdirectories when `<absolute-path>` is a directory
- `--allow-dev` — allow copying paths under `/dev`
- `--allow-sysfs` — allow copying paths under `/sys`
- `--allow-proc` — allow copying paths under `/proc`
- `--allow-symlinks` — upload symlinks as symlinks over HTTP(S)
- `--insecure` — disable TLS certificate and hostname verification for HTTPS output
- `--verbose` — print transfer progress; preferred at the top level

## Constraints

- Exactly one remote output target is required:
  - `--output-tcp` **or** `--output-http` **or** `--output-https`
- `--output-http` and `--output-https` are mutually exclusive
- Directory uploads require `--output-http` or `--output-https`
- Paths under `/dev`, `/sys`, and `/proc` require their corresponding allow flags
- Symlinks are skipped unless `--allow-symlinks` is provided
- `--output-format` does not affect this subcommand; transfers are raw file bytes

## Examples

```bash
./embedded_linux_audit --output-tcp 192.168.1.50:5000 linux remote-copy /tmp/fw.bin
./embedded_linux_audit --output-http http://192.168.1.50:5000/upload linux remote-copy /tmp/fw.bin
./embedded_linux_audit --output-https https://192.168.1.50:5443/upload linux remote-copy /tmp/fw.bin
./embedded_linux_audit --output-https https://192.168.1.50:5443/upload --verbose linux remote-copy /tmp/fw.bin --insecure
./embedded_linux_audit --output-http http://192.168.1.50:5000/upload linux remote-copy /tmp/fw_dir --recursive
./embedded_linux_audit --output-http http://192.168.1.50:5000/upload linux remote-copy /proc/device-tree --recursive --allow-proc
./embedded_linux_audit --output-http http://192.168.1.50:5000/upload linux remote-copy /tmp/link_to_fw --allow-symlinks
```
