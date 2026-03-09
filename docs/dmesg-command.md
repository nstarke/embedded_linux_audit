# `embedded_linux_audit linux dmesg` Command

Runs `dmesg` and emits kernel ring buffer output.

## `dmesg` arguments

- `--verbose` — enable verbose logging for command execution and remote HTTP(S) POST behavior
- `--output-tcp <IPv4:port>` — duplicate dmesg output to TCP destination
- `--output-http <http://host:port/path>` — duplicate dmesg output to HTTP endpoint via POST
- `--output-https <https://host:port/path>` — duplicate dmesg output to HTTPS endpoint via POST
- `--insecure` — disable TLS certificate and hostname verification for HTTPS output

## Notes

- `--output-format` does not change `dmesg` output behavior.
- For this subcommand, HTTP/HTTPS remote output always uses `Content-Type: text/plain; charset=utf-8`.
- If `--output-format` is explicitly set with `dmesg`, a warning is logged.

## `dmesg` examples

```bash
./embedded_linux_audit linux dmesg
./embedded_linux_audit linux dmesg --verbose
./embedded_linux_audit linux dmesg --output-tcp 192.168.1.50:5001
./embedded_linux_audit linux dmesg --output-http http://192.168.1.50:5000/dmesg
./embedded_linux_audit linux dmesg --output-https https://192.168.1.50:5443/dmesg
./embedded_linux_audit --output-format json linux dmesg
```