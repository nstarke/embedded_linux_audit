# uboot_audit

This repo provides a Linux host-side C utility for U-Boot-related flash analysis:

- `uboot_audit env`: find U-Boot environment candidates and print `fw_env.config` lines.
- `uboot_audit image`: find likely U-Boot image headers, optionally pull image bytes, or resolve load address.

Both tools are intended for embedded/Linux recovery and diagnostics workflows.

---

## Build

Build binary:

```bash
make env
```

Build binary (alias):

```bash
make image
```

Build both:

```bash
make
```

Static build:

```bash
make static
```

Clean:

```bash
make clean
```

Cross compile example:

```bash
make CC=arm-linux-gnueabi-gcc
```

---

## `uboot_audit env`

Scans MTD/UBI plus block devices (SD/eMMC such as `/dev/sd*` and `/dev/mmcblk*`) for blocks that resemble a valid U-Boot environment (CRC-verified by default), then prints candidate `fw_env.config` lines.

### `env` arguments

- `--verbose` — print scan progress and non-hit details
- `--size <env_size>` — fixed environment size (for example `0x10000`)
- `--hint <hint>` — override hint string used for positive labeling
- `--dev <device>` — scan only one device (step inferred from sysfs/proc)
- `--brutefoce` / `--bruteforce` — skip CRC checks and match by hint strings only
- `--skip-remove` — keep any created helper `/dev/mtdblock*`/UBI device nodes after run
- `--skip-mtd` — skip MTD/mtdblock scan targets and helper node handling
- `--skip-ubi` — skip UBI/ubiblock scan targets and helper node handling
- `--skip-sd` — skip `/dev/sd*` scan targets
- `--skip-emmc` — skip `/dev/mmcblk*` scan targets
- `--parse-vars` — print parsed key/value variables from candidate environments
- `--output-config[=<path>]` — write discovered `fw_env.config` lines to file (default `fw_env.config`)
- `--output-tcp <IPv4:port>` — duplicate output to TCP destination
- `--write <path>` — apply env updates from text file (native `fw_setenv`-style behavior)

### `--write` behavior

- Uses `./fw_env.config` for write settings.
  - If `./fw_env.config` exists, it is used directly.
  - If it does not exist, the tool first runs scan logic to generate it, then writes.
- Input file format (similar to `fw_setenv -s`):
  - `name=value` or `name value` → set variable
  - `name` (no value) → delete variable
  - blank lines and `#` comments are ignored
- Validations performed:
  - variable name must be non-empty
  - variable name must not contain `=`
  - variable name must not contain whitespace or control characters
  - sensitive variable updates/deletes require interactive confirmation:
    - prompt: `Modifying $ENVIRONMENT_VARIABLE_NAME might render the host unbootable.  Do you wish to proceed?`
    - only `Y`/`y` proceeds; any other response skips that variable write/delete
  - existing environment CRC must be valid before writing
  - updated environment must fit configured environment size
- CRC is recalculated and written back (standard or redundant layout detected from existing env data).

### `env` examples

```bash
./uboot_audit env
./uboot_audit env --verbose
./uboot_audit env --size 0x10000
./uboot_audit env --dev /dev/mtd3 --size 0x10000
./uboot_audit env --size 0x10000 /dev/mtd0:0x10000 /dev/mtd1:0x20000
./uboot_audit env --output-tcp 192.168.1.50:5000 --verbose
./uboot_audit env --write ./new_env.txt
```

Example candidate line:

```text
fw_env.config line: /dev/mtd0 0x40000 0x10000 0x10000 0x1
```

---

## `uboot_audit image`

Scans MTD/UBI and block devices (SD/eMMC such as `/dev/sd*` and `/dev/mmcblk*`) for likely U-Boot image signatures. FIT/uImage checks are validated structurally to reduce false positives.

### `image` arguments

- `--verbose` — print scan progress
- `--dev <device>` — restrict scan or action to one device
- `--step <bytes>` — scan stride (default `0x1000`)
- `--allow-text` — also match plain `U-Boot` text (higher false-positive risk)
- `--skip-remove` — keep any helper `/dev` nodes created during scan
- `--skip-mtd` — skip MTD/mtdblock scan targets
- `--skip-ubi` — skip UBI/ubiblock scan targets
- `--skip-sd` — skip `/dev/sd*` scan targets
- `--skip-emmc` — skip `/dev/mmcblk*` scan targets
- `--send-logs` — send tool logs over TCP using `--output-tcp <IPv4:port>`
- `--pull` — pull image bytes from `--dev` at `--offset` and send over TCP to `--output-tcp`
- `--offset <bytes>` — image offset used by `--pull` or `--find-address`
- `--output-tcp <IPv4:port>` — TCP destination used by `--pull`
- `--find-address` — parse image at `--offset` and print load address (uImage/FIT)

### `image` argument constraints

- `--pull` **requires**:
  - `--dev`
  - `--offset`
  - `--output-tcp`
- `--find-address` **requires**:
  - `--dev`
  - `--offset`
- `--find-address` **cannot** be combined with:
  - `--pull`
  - `--output-tcp` (unless `--send-logs` is also set)
- `--send-logs` **requires**:
  - `--output-tcp`
- `--send-logs` **cannot** be combined with:
  - `--pull`

### `image` examples

Scan all MTD devices:

```bash
./uboot_audit image --verbose
```

Scan one device:

```bash
./uboot_audit image --dev /dev/mtdblock4 --step 0x1000
```

Find load address at known offset:

```bash
./uboot_audit image --find-address --dev /dev/mtdblock4 --offset 0x200
```

Send scan logs over TCP:

```bash
./uboot_audit image --verbose --send-logs --output-tcp 192.168.1.50:5000
```

Pull image bytes to TCP listener:

```bash
./uboot_audit image --pull --dev /dev/mtdblock4 --offset 0x200 --output-tcp 192.168.1.50:5000
```

---

## Notes / cautions

- Run as root (raw flash/block reads and device-node operations typically require it).
- Both tools report candidates and parsed results; always validate before destructive operations.
- Be careful with `fw_setenv` on production hardware.