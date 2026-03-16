# embedded_linux_audit

[![Build](https://github.com/nstarke/embedded_linux_audit/actions/workflows/release-cross-static.yml/badge.svg?branch=main)](https://github.com/nstarke/embedded_linux_audit/actions/workflows/release-cross-static.yml)
[![Agent Tests](https://github.com/nstarke/embedded_linux_audit/actions/workflows/agent-tests.yml/badge.svg?branch=main)](https://github.com/nstarke/embedded_linux_audit/actions/workflows/agent-tests.yml)

![embedded_linux_audit logo](images/logo.png)

`embedded_linux_audit` (`ela`) is a static C binary for security assessment of embedded Linux devices. It runs directly on the target — no runtime dependencies, no package manager, no installation required — and covers U-Boot analysis, Linux system introspection, EFI/BIOS option ROM inspection, TPM 2.0 interrogation, and remote exfiltration of collected data.

## Command groups

### `uboot` — Boot environment and image analysis

| Subcommand | Description |
|---|---|
| `uboot env` | Scan MTD/UBI/block devices for U-Boot environment partitions; emit `fw_env.config` entries and raw variable dumps |
| `uboot image` | Detect uImage and FIT headers on flash/block devices; resolve load addresses and extract image bytes |
| `uboot audit` | Run compiled security rules against U-Boot environment data to check Secure Boot posture, environment write-protection, and command-line integrity |

### `linux` — Operating system introspection

| Subcommand | Description |
|---|---|
| `linux dmesg` | Capture the kernel ring buffer; `dmesg watch` for continuous streaming |
| `linux execute-command` | Run an arbitrary shell command and collect output |
| `linux list-files` | Enumerate files under a path (optionally recursive) |
| `linux list-symlinks` | Enumerate symbolic links under a path (optionally recursive) |
| `linux grep` | Search file contents under a directory for a pattern |
| `linux download-file` | Fetch a file from an HTTP(S) URL to a local path |
| `linux remote-copy` | Upload a local file to a remote HTTP(S) endpoint |
| `linux ssh client` | Open an interactive SSH session (via libssh) |
| `linux ssh copy` | Transfer files over SFTP |
| `linux ssh tunnel` | Establish a reverse SSH tunnel |
| `linux ssh socks` | Set up a SOCKS proxy over SSH |

### `efi` — EFI/UEFI inspection

| Subcommand | Description |
|---|---|
| `efi dump-vars` | Enumerate all EFI runtime variables with attributes and decoded values |
| `efi orom` | List and extract EFI PCI option ROMs |

### `bios` — Legacy BIOS inspection

| Subcommand | Description |
|---|---|
| `bios orom` | List and extract legacy PCI option ROMs |

### `tpm2` — TPM 2.0 interrogation

| Subcommand | Description |
|---|---|
| `tpm2 getcap` | Query TPM capabilities and properties |
| `tpm2 pcrread` | Read PCR values |
| `tpm2 nvreadpublic` | Read NV index metadata |
| `tpm2 createprimary` | Create a primary object and serialize the context |

### `transfer` — Remote terminal and data exfiltration

| Subcommand | Description |
|---|---|
| `transfer --remote <host:port>` | Connect to a TCP listener, transfer the agent binary, and drop into an interactive session |
| `transfer --remote ws[s]://...` | Connect over WebSocket (plain or TLS) to the ELA terminal server and start an interactive session |

## Interactive shell

Running `ela` with no arguments starts a REPL that exposes all command groups above, supports tab completion (when built with readline), maintains command history, and provides a `set` built-in for configuring per-session environment variables (`ELA_API_URL`, `ELA_OUTPUT_FORMAT`, `ELA_QUIET`, etc.).

## Global flags

| Flag | Description |
|---|---|
| `--output-format <txt\|csv\|json>` | Output encoding (default: `txt`) |
| `--output-tcp <ip:port>` | Stream command output to a TCP listener |
| `--output-http <url>` | POST command output to an HTTP(S) endpoint |
| `--script <path\|url>` | Execute commands from a local or remote script file |
| `--remote <target>` | Connect to a reverse-shell/WebSocket terminal before starting |
| `--api-key <key>` | Bearer token for API server authentication |
| `--insecure` | Disable TLS certificate and hostname verification |
| `--quiet` | Suppress informational output |

API keys are also read from the `ELA_API_KEY` environment variable or `/tmp/ela.key`.

## Companion server components

### Agent helper API (`api/agent/`)

A Node.js HTTP(S) server that acts as a collection point for agent data and a distribution server for binaries and test scripts.

- Accepts `POST /:mac/upload/:type` for command output, dmesg, file contents, EFI variables, option ROM data, U-Boot images, and environment dumps
- Normalizes uploads into a PostgreSQL schema and stores raw payloads alongside relational records
- Optionally keeps runtime file artifacts under timestamped per-device directories in `api/agent/data/`
- Serves release binaries (with optional auto-download from GitHub), test scripts, and U-Boot environment files
- Optional bearer token authentication (`--validate-key`)
- Optional HTTPS with self-signed certificate (`--https`)

```bash
cd api/agent && npm install && npm start -- --host 0.0.0.0 --port 5000
```

See [docs/api/agent/helper-server.md](docs/api/agent/helper-server.md) for full options.

### WebSocket terminal server (`api/terminal/`)

A Node.js WebSocket server with a terminal TUI for managing multiple simultaneous agent sessions. Each agent that connects via `transfer --remote ws://...` appears as a named session the operator can attach to, send commands to, and detach from without dropping the connection.

```bash
cd api/terminal && npm install && npm start
```

See [docs/api/terminal/index.md](docs/api/terminal/index.md).

### nginx reverse proxy (`nginx/ela.conf`)

An example nginx configuration that exposes both server components behind a single frontend — HTTP on port 80 and HTTPS on port 443 — routing `/terminal/<mac>` to the WebSocket terminal server and everything else to the agent helper API.

See [docs/api/nginx.md](docs/api/nginx.md).

## Docker Deployment

The repository now includes a containerized deployment path with PostgreSQL, the agent API, the terminal WebSocket API, and nginx fronting both services.

```bash
docker compose up --build
```

The default stack exposes:

- `http://localhost/` → agent helper API
- `http://localhost/terminal/<mac>` → terminal WebSocket endpoint

The agent API container runs database migrations automatically on startup. Compose defaults target the bundled PostgreSQL container using the `ela`/`ela` credentials defined in `docker-compose.yml`.

## Portable static release builds

GitHub Releases contain fully static binaries for the following architectures, compiled via Zig + musl cross-compilation:

`x86_64` · `x86` · `arm32-le` · `arm32-be` · `aarch64-le` · `aarch64-be` · `mips-le` · `mips-be` · `mips64-le` · `mips64-be` · `powerpc-le` · `powerpc64-be` · `powerpc-be` · `riscv32` · `riscv64`

No target-side dependencies. Drop the binary on the device and run it.

See [docs/agent/getting-started/build.md](docs/agent/getting-started/build.md) for the full build matrix and local build instructions.

## Documentation

- [Documentation index](docs/index.md)
- [Manual assessment checklist](docs/manual-checklist.md)

## Licensing

- The `embedded_linux_audit` agent and associated build/test material: **GPL-3.0-or-later** ([COPYING](COPYING))
- The helper API under `api/` and other non-agent files: **MIT** ([LICENSE.api](LICENSE.api))
- Third-party code under `third_party/`: each component's own license

See [LICENSE](LICENSE) for the full breakdown.
