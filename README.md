# fw_env_scan

`fw_env_scan` is a small Linux host utility that scans MTD devices for data that looks like a valid U-Boot environment block.

Its main purpose is to help you build a correct `fw_env.config` entry for U-Boot user-space tools:

- `fw_printenv`
- `fw_setenv`

When it finds a CRC-valid candidate, it prints a ready-to-copy line in the exact format expected by `fw_env.config`:

```text
fw_env.config line: <device> <offset> <env_size> <erase_size>
```

---

## Why this is useful

The U-Boot tools require an accurate `fw_env.config` definition. If any field is wrong (device, offset, env size, or erase size), `fw_printenv/fw_setenv` may fail or target the wrong flash region.

`fw_env_scan` helps by:

1. Walking `/dev/mtd*` / `/dev/mtdblock*` devices (or explicit devices you pass).
2. Reading blocks at erase-size boundaries.
3. Checking whether the block contains a valid U-Boot environment CRC.
4. Printing candidate `fw_env.config` lines you can test directly.

---

## Build

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

---

## Usage

Auto-scan MTD devices and try common environment sizes:

```bash
./fw_env_scan
```

Scan with a fixed environment size:

```bash
./fw_env_scan -s 0x10000
```

Scan specific device(s) with explicit erase step:

```bash
./fw_env_scan -s 0x10000 /dev/mtd0:0x10000 /dev/mtd1:0x20000
```

---

## Example output

```text
candidate offset=0x40000  crc=LE-endian  (has known vars)
  fw_env.config line: /dev/mtd0 0x40000 0x10000 0x10000
```

You can then place that line in `/etc/fw_env.config` (or your target config path) and validate with:

```bash
fw_printenv
```

---

## Notes and cautions

- This tool finds **candidates** based on CRC and common environment hints; always validate on your platform.
- Some platforms use redundant environments (two entries); you may see multiple valid candidates.
- Be careful before using `fw_setenv` on production hardware—verify the selected region first.
