# embedded_linux_audit

[![Build](https://github.com/nstarke/embedded_linux_audit/actions/workflows/release-cross-static.yml/badge.svg?branch=main)](https://github.com/nstarke/embedded_linux_audit/actions/workflows/release-cross-static.yml)
[![Agent Tests](https://github.com/nstarke/embedded_linux_audit/actions/workflows/agent-tests.yml/badge.svg?branch=main)](https://github.com/nstarke/embedded_linux_audit/actions/workflows/agent-tests.yml)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/32974/badge.svg)](https://scan.coverity.com/projects/32974)
[![codecov](https://codecov.io/gh/nstarke/embedded_linux_audit/branch/main/graph/badge.svg)](https://codecov.io/gh/nstarke/embedded_linux_audit)
[![CodeQL](https://github.com/nstarke/embedded_linux_audit/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/nstarke/embedded_linux_audit/actions/workflows/codeql.yml)
[![cppcheck](https://github.com/nstarke/embedded_linux_audit/actions/workflows/cppcheck.yml/badge.svg?branch=main)](https://github.com/nstarke/embedded_linux_audit/actions/workflows/cppcheck.yml)
[![npm audit](https://github.com/nstarke/embedded_linux_audit/actions/workflows/npm-audit.yml/badge.svg?branch=main)](https://github.com/nstarke/embedded_linux_audit/actions/workflows/npm-audit.yml)
[![Dependabot enabled](https://img.shields.io/badge/dependabot-enabled-025e8c?logo=dependabot)](https://github.com/nstarke/embedded_linux_audit/blob/main/.github/dependabot.yml)

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
| `linux netstat` | List listening and active TCP/UDP sockets with PID/program data |
| `linux remote-copy` | Upload a local file to a remote HTTP(S) endpoint |
| `linux pcap` | Capture packets from an interface as pcap data; stream to the agent API over WebSocket when `--output-http` is configured |
| `linux coredump` | Configure kernel coredump collection to `/tmp`; with `--output-http`, POST captured cores to the agent API |
| `linux ssh client` | Open an interactive SSH session (via libssh) |
| `linux ssh copy` | Transfer files over SFTP |
| `linux ssh tunnel` | Establish a reverse SSH tunnel |
| `linux ssh socks` | Set up a SOCKS proxy over SSH |
| `linux process watch on <needle>` | Start watching for processes whose command line matches `<needle>`; emits a record each time the matching PID set changes (restart detected) |
| `linux process watch off <needle>` | Stop watching a previously registered needle |
| `linux process watch list` | List all active needles and their current matching PIDs |
| `linux gdbserver <PID> <PORT>` | Attach to a running process and expose a GDB remote stub on the given TCP port; connect with `target remote <agent-ip>:<PORT>` in `gdb-multiarch` |
| `linux modules` | List, load, unload, and inspect kernel modules directly through `/proc/modules`, module files, and module syscalls |

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

### `spi` — SPI device inspection

| Subcommand | Description |
|---|---|
| `spi list` | Enumerate SPI devices and indexed SPI-backed MTD devices through `ela_kmod` |
| `spi dump <DUMP_FILE_PATH> [DEVICE_INDEX]` | Dump the selected index from `spi list`; without an index, dump the largest unambiguous SPI-backed MTD device |

### `nand flash` — NAND flash inspection

| Subcommand | Description |
|---|---|
| `nand flash list` | Enumerate indexed SLC/MLC/TLC NAND MTD devices and geometry through `ela_kmod` |
| `nand flash dump <DUMP_FILE_PATH> [DEVICE_INDEX]` | Dump corrected main-area data through `ela_kmod`; bad eraseblocks are padded with `0xff` and OOB data is excluded |

### `emmc` — eMMC inspection

| Subcommand | Description |
|---|---|
| `emmc list` | Enumerate indexed whole eMMC user-area block devices through `ela_kmod`; SD cards, partitions, boot areas, and RPMB are excluded |
| `emmc dump <DUMP_FILE_PATH> [DEVICE_INDEX]` | Dump the selected eMMC user area through `ela_kmod`; without an index, dump the largest unambiguous device |

### `orom` — Kernel PCI option ROM inspection

| Subcommand | Description |
|---|---|
| `orom list` | Enumerate indexed PCI option ROMs that `ela_kmod` can map through the kernel PCI layer |
| `orom dump <DUMP_FILE_PATH> [DEVICE_INDEX]` | Dump the selected mapped PCI option ROM; without an index, dump the largest unambiguous ROM |

### `usb` — Kernel USB inspection and capture

| Subcommand | Description |
|---|---|
| `usb list` | Enumerate the complete kernel USB device tree and print indices for the current snapshot |
| `usb reset <DEVICE_INDEX>` | Reset a device selected from `usb list` through the kernel USB core |
| `usb port list` | Enumerate hub ports, connection state, power state, and attached child devices |
| `usb port reset <PORT_INDEX>` | Reset the attached device on a port selected from `usb port list` |
| `usb port power-cycle <PORT_INDEX>` | Clear and restore a hub port's power feature; actual VBUS switching depends on the hub hardware |
| `usb descriptor dump <DUMP_FILE_PATH> [DEVICE_INDEX]` | Dump cached raw device and configuration descriptors through `ela_kmod` |
| `usb pcap <DUMP_FILE_PATH> [BUS_NUMBER]` | Capture kernel usbmon traffic to pcap until interrupted; omit the bus to capture all buses |

### Kernel-backed hardware command requirements

The `spi`, `nand flash`, `emmc`, top-level `orom`, and USB hardware commands
do not read sysfs or the underlying hardware device nodes directly. They open
`/dev/ela_physmem` and perform their operations through the `ela_kmod` ioctl
interface. Build and load a module matching the running kernel before using
them:

```sh
make -C kmod
sudo insmod kmod/ela_kmod.ko
```

The module device is mode `0600`, and opening it also requires
`CAP_SYS_RAWIO`. On systems without devtmpfs, create the `/dev/ela_physmem`
misc-device node using the dynamic minor reported for `ela_physmem` in
`/proc/misc`.

`DEVICE_INDEX` is the zero-based `index=N` printed by the corresponding
`list` command. When it is omitted, `dump` selects the unique largest readable
candidate and refuses ambiguous ties. Run `list` and pass an explicit index
when more than one device is present.

```sh
./embedded_linux_audit spi list
./embedded_linux_audit spi dump /tmp/spi.bin 0
./embedded_linux_audit nand flash list
./embedded_linux_audit nand flash dump /tmp/nand.bin 0
./embedded_linux_audit emmc list
./embedded_linux_audit emmc dump /tmp/emmc.bin 0
./embedded_linux_audit orom list
./embedded_linux_audit orom dump /tmp/orom.bin 0
./embedded_linux_audit usb list
./embedded_linux_audit usb descriptor dump /tmp/usb-descriptors.bin 1
./embedded_linux_audit usb port list
```

The dump formats are deliberately different: SPI uses an SPI-backed MTD;
NAND returns corrected main-area data, preserves physical offsets by filling
marked bad eraseblocks with `0xff`, and excludes OOB bytes; eMMC returns the
whole managed user area while excluding SD cards, partitions, boot areas, and
RPMB; `orom` returns the PCI expansion-ROM mapping supplied by the kernel PCI
layer. The eMMC block-layer implementation requires Linux 6.9 or newer.

Top-level `orom` is distinct from `efi orom` and `bios orom`: the latter scan
the sysfs PCI ROM attributes and filter images by firmware type, while
top-level `orom` uses `pci_map_rom()` in `ela_kmod` and dumps the mapped ROM
without EFI/legacy filtering.

USB pcap capture is kernel-backed through `usbmon`, but does not use
`ela_kmod`. The target kernel must enable `CONFIG_USB_MON`; load `usbmon` when
it is modular and ensure the caller can open the usbmon capture interface.
`BUS_NUMBER` is the numeric bus printed by `usb list`; omit it to use
`usbmon0`, which captures every USB bus. Stop capture with `Ctrl-C` or
`SIGTERM`. Capture files are created mode `0600` in libpcap format.

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
| `--output-http <url>` | POST command output to an HTTP(S) endpoint; `linux pcap` uses the same base URL to open `ws(s)://.../pcap/<mac>` |
| `--script <path\|url>` | Execute commands from a local or remote script file |
| `--remote <target>` | Connect to a reverse-shell/WebSocket terminal before starting |
| `--api-key <key>` | Bearer token for API server authentication |
| `--insecure` | Disable TLS certificate and hostname verification |
| `--quiet` | Suppress informational output |

API keys are also read from the `ELA_API_KEY` environment variable or `/tmp/ela.key`.

## Companion server components

### Agent helper API (`api/agent/`)

A Node.js HTTP(S) server that acts as a collection point for agent data and a distribution server for binaries and test scripts.

- Accepts `POST /:mac/upload/:type` for command output, dmesg, coredumps, file contents, EFI variables, option ROM data, U-Boot images, and environment dumps
- Accepts `ws(s)://host/pcap/<mac>` for streaming `linux pcap` captures as binary pcap data
- Normalizes uploads into a PostgreSQL schema and stores raw payloads alongside relational records
- Optionally keeps runtime file artifacts under timestamped per-device directories in `api/agent/data/`
- Serves release binaries (with optional auto-download from GitHub), test scripts, and U-Boot environment files
- Optional bearer token authentication (`--validate-key`)
- Optional HTTPS with self-signed certificate (`--https`)

```bash
cd api/agent && npm install && npm start -- --host 0.0.0.0 --port 5000
```

To reuse the latest timestamped artifact directory instead of creating a new one on startup:

```bash
cd api/agent && npm start -- --reuse-last-data-dir
```

See [docs/api/agent/helper-server.md](docs/api/agent/helper-server.md) for full options.

### WebSocket terminal server (`api/terminal/`)

A Node.js WebSocket server with a terminal TUI for managing multiple simultaneous agent sessions. Each agent that connects via `transfer --remote ws://...` appears as a named session the operator can attach to, send commands to, and detach from without dropping the connection.

- Persists terminal connection events in PostgreSQL
- Stores operator-assigned device aliases in PostgreSQL and maps them to upload records by MAC address

```bash
cd api/terminal && npm install && npm start
```

See [docs/api/terminal/index.md](docs/api/terminal/index.md).

### nginx reverse proxy (`nginx/ela.conf`)

An example nginx configuration that exposes the server components behind a single frontend — HTTP on port 80 and HTTPS on port 443 — routing `/terminal/<mac>` to the WebSocket terminal server, `/gdb/` to the GDB bridge, `/pcap/<mac>` to the agent API WebSocket receiver, and everything else to the agent helper API.

See [docs/api/nginx.md](docs/api/nginx.md).

## Docker Deployment

The repository now includes a containerized deployment path with PostgreSQL, the agent API, the terminal WebSocket API, and nginx fronting both services.

```bash
docker compose up --build
```

The default stack exposes:

- `http://localhost/` → agent helper API
- `http://localhost/terminal/<mac>` → terminal WebSocket endpoint
- `http://localhost/pcap/<mac>` → pcap capture WebSocket endpoint

The agent API container runs database migrations automatically on startup. Compose defaults target the bundled PostgreSQL container (defined in `docker-compose.override.yml`) using the `ela`/`ela` credentials.

To use an existing PostgreSQL server instead of the bundled container, set `ELA_DB_HOST` (and the other `ELA_DB_*` variables) and start the base file only — `ELA_DB_HOST=db.example.com docker compose -f docker-compose.yml up -d` — or pass `--db-host` to `nginx/install.sh`. See [docs/api/docker-operations.md](docs/api/docker-operations.md#external-postgresql).

For operational details, see [docs/api/docker-operations.md](/home/nick/Documents/git/embedded_linux_audit/docs/api/docker-operations.md).

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
