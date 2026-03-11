# `embedded_linux_audit linux download-file` Command

Downloads a file from HTTP or HTTPS to a local path on the host running `embedded_linux_audit`.

This subcommand writes bytes directly to the specified local file. It does **not** emit the downloaded payload to standard output or remote output targets.

## `download-file` arguments

- `<http(s)-url>` — required source URL; must begin with `http://` or `https://`
- `<output-path>` — required destination path on the local filesystem
- `--insecure` — top-level global option to disable TLS certificate and hostname verification for HTTPS downloads
- `--quiet` — top-level global option to suppress verbose transfer logging

## Notes

- `--output-format` does not affect `download-file`; the payload is written to the local file path.
- If `--output-format` is explicitly set, the tool warns that it has no effect for this subcommand.
- On completion, the command logs a summary like `download-file downloaded <bytes> bytes success=<true|false> ...` to stderr.
- The destination file is overwritten if the download helper writes successfully to that path.

## Examples

```bash
./embedded_linux_audit linux download-file http://192.168.1.50/fw.bin /tmp/fw.bin
./embedded_linux_audit linux download-file https://example.com/releases/fw.bin /tmp/fw.bin
./embedded_linux_audit --insecure linux download-file https://192.168.1.50/fw.bin /tmp/fw.bin
./embedded_linux_audit --quiet linux download-file http://192.168.1.50/fw.bin /tmp/fw.bin
./embedded_linux_audit --output-format json linux download-file https://example.com/fw.bin /tmp/fw.bin
```