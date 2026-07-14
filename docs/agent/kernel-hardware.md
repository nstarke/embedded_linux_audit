# Kernel-Backed Hardware Commands

The `spi`, `nand flash`, `emmc`, top-level `orom`, and USB hardware command
groups perform operations through `ela_kmod`. They do not use sysfs or open
the underlying MTD/block/USB devices from userspace. `usb pcap` is the one
exception: it uses the kernel usbmon capture interface through libpcap.

`ela_kmod` also hosts the WLAN firmware-command injection shim used by
[`linux wlan fuzz --target ath10k`](linux/wlan-fuzz.md) (a kprobe-based
facility, built only when the kernel has `CONFIG_KPROBES`). Loading the module
is the same as below; the shim is armed at runtime by the fuzzer and is
otherwise inert.

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

## USB

```text
usb list
usb reset <DEVICE_INDEX>
usb port list
usb port reset <PORT_INDEX>
usb port power-cycle <PORT_INDEX>
usb descriptor dump <DUMP_FILE_PATH> [DEVICE_INDEX]
usb pcap <DUMP_FILE_PATH> [BUS_NUMBER]
```

`usb list` walks the kernel USB device tree, including root hubs, and reports
bus/device addresses, parent and port topology, speed, IDs, class information,
and cached strings. Device indices are snapshots: enumerate again after a
reset, disconnect, reconnect, or power cycle because USB device addresses and
indices can change.

`usb reset` invokes the coordinated kernel USB reset path for the selected
device. `usb port list` provides a separate zero-based port index and reports
the raw USB hub status/change words plus decoded connection, enable, and power
state. Port reset resets the currently attached child. Port power-cycle sends
hub class requests to clear and restore the port power feature. Many hubs gang
power across several ports or do not physically switch VBUS, so support and
electrical behavior are hardware-dependent. Both operations can disconnect
devices and disrupt mounted storage, network links, input devices, and other
active users.

The descriptor dump is the cached binary device descriptor followed by each
cached raw configuration descriptor blob. It avoids issuing descriptor reads
to a potentially unstable device. Without an explicit device index, it only
selects a target when exactly one non-root USB device exists. The output file
is local, mode `0600`, and is truncated only after target selection and the
kernel read succeed.

`usb pcap` captures USB Request Blocks through the kernel usbmon facility and
writes a standard libpcap savefile until `Ctrl-C` or `SIGTERM`. The kernel must
enable `CONFIG_USB_MON`; load the `usbmon` module when applicable and provide
the permissions needed by libpcap to open the monitor source. With no bus
argument it captures `usbmon0` (all buses). Otherwise it captures
`usbmonBUS_NUMBER`, where the number is the `bus=N` value from `usb list`.
This command does not open `/dev/ela_physmem` and does not require `ela_kmod`.

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
embedded_linux_audit usb list
embedded_linux_audit usb reset 3
embedded_linux_audit usb port list
embedded_linux_audit usb descriptor dump /tmp/usb-descriptors.bin 3
embedded_linux_audit usb pcap /tmp/usb.pcap 1
```
