# Output Formats and Remote Output

Global options:

- `--output-format <csv|json|txt>` — select requested output format at the `embedded_linux_audit` wrapper level (default: `txt`)
- `--verbose` — enable verbose logging at the `embedded_linux_audit` wrapper level for commands/subcommands that support it
- `--output-tcp <ip:port>` — configure a TCP remote output destination at the `embedded_linux_audit` wrapper level
- `--output-http <http://host:port/path>` — configure an HTTP remote output destination at the `embedded_linux_audit` wrapper level
- `--output-https <https://host:port/path>` — configure an HTTPS remote output destination at the `embedded_linux_audit` wrapper level
  - `txt`: existing human-readable output
  - `csv`: comma-separated records (header + rows)
  - `json`: newline-delimited JSON objects (one JSON object per line)
  - when `--verbose` is enabled with `csv`/`json`, verbose messages are emitted as structured `verbose` records (instead of plain text lines)

These wrapper-level options apply to all commands and subcommands. Individual subcommands may still accept the same flags for backward compatibility/override behavior, but the preferred form is to pass them before the command group, for example:

- `./embedded_linux_audit --verbose uboot env`
- `./embedded_linux_audit --output-http http://127.0.0.1:5000/dmesg linux dmesg`
- `./embedded_linux_audit --output-tcp 127.0.0.1:5001 bios orom list`

Remote output notes:

- `./embedded_linux_audit --output-tcp <ip:port> uboot env` sends the same formatted stream selected by `--output-format` over TCP.
- `./embedded_linux_audit --output-http <http://host:port/path> uboot env` sends the same formatted stream selected by `--output-format` in a single HTTP POST request.
- `./embedded_linux_audit --output-https <https://host:port/path> uboot env` sends the same formatted stream selected by `--output-format` in a single HTTPS POST request using embedded CA certificates.
- `uboot env --insecure` disables TLS certificate and hostname verification for HTTPS output.
- `./embedded_linux_audit --output-tcp ... uboot image pull ...` is used for `pull` binary streaming; for formatted scan/find-address output over TCP, use `./embedded_linux_audit --output-tcp ... uboot image --send-logs ...`.
- `./embedded_linux_audit --output-http <http://host:port/path> uboot image ...` can be used to POST formatted scan/find-address output, or to POST pulled image bytes when used with `pull`.
- `./embedded_linux_audit --output-https <https://host:port/path> uboot image ...` can be used to POST formatted scan/find-address output, or to POST pulled image bytes when used with `pull`, using embedded CA certificates.
- `uboot image --insecure` disables TLS certificate and hostname verification for HTTPS output.
- `./embedded_linux_audit --output-tcp <ip:port> linux dmesg` sends dmesg text output to TCP.
- `./embedded_linux_audit --output-http <http://host:port/path> linux dmesg` sends dmesg text output in a single HTTP POST request with `Content-Type: text/plain; charset=utf-8`.
- `./embedded_linux_audit --output-https <https://host:port/path> linux dmesg` sends dmesg text output in a single HTTPS POST request with `Content-Type: text/plain; charset=utf-8`, using embedded CA certificates.
- `linux dmesg --insecure` disables TLS certificate and hostname verification for HTTPS output.
- `--output-format` does not affect `linux dmesg`; if specified, a warning is emitted.
- `./embedded_linux_audit --output-tcp <ip:port> linux remote-copy <path>` sends raw file bytes over TCP.
- `./embedded_linux_audit --output-http <http://host:port/path> linux remote-copy <path>` sends raw file bytes in a single HTTP POST request with `Content-Type: application/octet-stream`.
- `./embedded_linux_audit --output-https <https://host:port/path> linux remote-copy <path>` sends raw file bytes in a single HTTPS POST request with `Content-Type: application/octet-stream`, using embedded CA certificates.
- `linux remote-copy --insecure` disables TLS certificate and hostname verification for HTTPS output.
- `--output-format` does not affect `linux remote-copy`; if specified, a warning is emitted.
- `./embedded_linux_audit --output-tcp <ip:port> efi orom pull` sends matching EFI option ROM payloads over TCP.
- `./embedded_linux_audit --output-http <http://host:port/path> efi orom pull` sends matching EFI option ROM payloads via HTTP POST with `Content-Type: application/octet-stream`.
- `./embedded_linux_audit --output-https <https://host:port/path> efi orom pull` sends matching EFI option ROM payloads via HTTPS POST with `Content-Type: application/octet-stream`, using embedded CA certificates.
- `./embedded_linux_audit --output-tcp <ip:port> bios orom pull` sends matching BIOS option ROM payloads over TCP.
- `./embedded_linux_audit --output-http <http://host:port/path> bios orom pull` sends matching BIOS option ROM payloads via HTTP POST with `Content-Type: application/octet-stream`.
- `./embedded_linux_audit --output-https <https://host:port/path> bios orom pull` sends matching BIOS option ROM payloads via HTTPS POST with `Content-Type: application/octet-stream`, using embedded CA certificates.
- `efi orom list` and `bios orom list` honor `--output-format` and emit list records in txt/csv/json format.
- `efi|bios orom --insecure` disables TLS certificate and hostname verification for HTTPS output.
- `efi|bios orom` sends emitted output records and all log lines (including verbose logs) to the configured `--output-{tcp,http,https}` destination.
