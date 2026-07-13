# Kernel-Backed Hardware Commands

The `spi`, `nand flash`, `emmc`, and top-level `orom` command groups perform
hardware enumeration and reads through `ela_kmod`. They do not use sysfs or
open the underlying MTD/block devices from userspace.

## Requirements

Build the module against the headers for the running target kernel and load
it before invoking these commands:

```sh
make -C kmod
sudo insmod kmod/ela_kmod.ko
```

The commands open `/dev/ela_physmem`. The node is mode `0600`, and the module
also requires the caller to hold `CAP_SYS_RAWIO`. With devtmpfs, the device
node is created automatically. Otherwise, obtain the dynamic misc-device
minor from `/proc/misc` and create the node manually.

The userspace binary and module must use the same `ELA_KMOD_ABI_VERSION` from
`kmod/ela_ioctl.h`. An ABI mismatch is rejected with `EINVAL`.

## Device indices

Every `list` command prints a zero-based `index=N`. That index is the optional
last argument accepted by the matching `dump` command. Indices describe the
current enumeration and should be obtained again after hardware is added,
removed, rebound, or reprobed.

Without an explicit index, each dump command selects the unique largest
readable candidate. It fails rather than guessing when no candidate exists or
when multiple largest candidates have the same size.

Dump paths are local files created with mode `0600`. An existing path is
truncated after device selection succeeds. A hardware/read error can leave a
partial file, so callers should check the command exit status before using the
image. These commands currently emit plain-text list/progress output; global
structured output options do not change the binary dump format.

## SPI

```text
spi list
spi dump <DUMP_FILE_PATH> [DEVICE_INDEX]
```

`spi list` reports kernel SPI devices followed by indexed MTD devices whose
device ancestry includes SPI. Only the indexed SPI-backed MTD entries are
dump targets. `spi dump` reads the selected MTD through the kernel MTD layer.

## NAND flash

```text
nand flash list
nand flash dump <DUMP_FILE_PATH> [DEVICE_INDEX]
```

The list includes raw SLC and MLC/TLC NAND devices registered with MTD,
including parallel NAND and SPI-NAND. Geometry includes main-area size,
eraseblock size, page size, OOB size, and ECC strength.

The dump contains corrected main-area bytes and does not contain OOB data.
Marked bad eraseblocks are represented by `0xff` bytes so offsets in the file
continue to correspond to physical main-area offsets. Uncorrectable reads
fail the dump.

## eMMC

```text
emmc list
emmc dump <DUMP_FILE_PATH> [DEVICE_INDEX]
```

eMMC is managed NAND exposed through the MMC block layer, rather than raw
NAND exposed through MTD. The list contains whole eMMC user-area devices and
excludes removable SD cards, DOS/GPT partitions, eMMC boot areas, and RPMB.
The dump is a byte-for-byte image of the selected user area.

The current block-file implementation requires Linux 6.9 or newer. On older
kernels, the eMMC ioctls return `EOPNOTSUPP`.

## PCI option ROMs

```text
orom list
orom dump <DUMP_FILE_PATH> [DEVICE_INDEX]
```

Top-level `orom` enumerates PCI functions whose expansion ROM can be mapped
with the kernel PCI ROM API. List output includes BDF, vendor/device ID, PCI
class, and mapped size. Dump temporarily maps the selected expansion ROM,
copies its mapped bytes, and unmaps it after every request.

This path is separate from `efi orom` and `bios orom`. Those commands read PCI
ROM attributes from sysfs and filter images by EFI or legacy firmware type.
Top-level `orom` uses the kernel PCI layer and applies no image-type filter.
It can therefore help when the sysfs ROM attribute is missing or inaccessible,
but it still cannot read a device for which the kernel cannot map a ROM
resource.

## Examples

```sh
embedded_linux_audit spi list
embedded_linux_audit spi dump /tmp/spi.bin 1
embedded_linux_audit nand flash list
embedded_linux_audit nand flash dump /tmp/nand.bin 0
embedded_linux_audit emmc list
embedded_linux_audit emmc dump /tmp/emmc.bin 0
embedded_linux_audit orom list
embedded_linux_audit orom dump /tmp/orom.bin 2
```
