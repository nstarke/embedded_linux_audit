# `embedded_linux_audit linux wlan` Command

WLAN NIC tooling. `wlan list` enumerates the wireless NICs on the host and
reports which the fuzzer supports; `wlan fuzz` is a class-directed black-box
fuzzer for the host&rarr;firmware command interface of those NICs.

The fuzzer, instead of flipping random bits, mutates the semantic field classes
that WLAN firmware tends to trust from the host driver &mdash; array
**indices**, **lengths**, element **counts**, and trailing **arrays** &mdash;
using boundary values pivoted on the firmware's real array sizes (extracted
from the Linux driver headers).

> **Authorized use only.** Run this against your own hardware. It crashes
> device firmware by design (WLAN firmware lives in RAM; nothing is
> persistent). For the `ath10k` target the injection path runs inside the
> host kernel and can wedge or panic the host, not just the NIC.

## Targets

| Target | Device | Transport |
|---|---|---|
| `ath9k-htc` | Atheros AR9271/AR7010 | USB (raw usbfs) |
| `rtw88-usb` | RTL8723DU/8821CU/8822BU/CU | USB (raw usbfs) |
| `mwifiex-usb` | Marvell USB8766/8797/8801/8997 | USB (raw usbfs) |
| `mt7601u` | MediaTek MT7601U | USB (raw usbfs) |
| `carl9170` | Atheros AR9170 | USB (raw usbfs) |
| `rtl8xxxu` | RTL8723A/BU, RTL8188E/FU, RTL8192E/FU, RTL8710BU | USB (raw usbfs) |
| `ath10k` | Atheros/Qualcomm QCA988x/9377/9887/6174 (WMI) | PCIe/SDIO/USB via the `ela_kmod` kernel shim |
| `ath11k` | Qualcomm QCA6390/WCN6855/IPQ8074/QCN9074 (WMI-TLV) | PCIe/SDIO via the `ela_kmod` kernel shim |
| `ath12k` | Qualcomm WCN7850/QCN9274 Wi-Fi 7 (WMI-TLV) | PCIe via the `ela_kmod` kernel shim |
| `mt76` | MediaTek mt7615/mt7915/mt7921/mt7996 (connac MCU) | PCIe/SDIO via the `ela_kmod` kernel shim |
| `brcmfmac` | Broadcom BCM43xx/4356/4359/4373 (BCDC ioctls) | SDIO/PCIe/USB via the `ela_kmod` kernel shim |
| `usb-generic` | Any USB NIC by VID:PID (proprietary/unknown) | USB (raw usbfs), **blind** &mdash; no command grammar |
| `wext-generic` | Any WEXT NIC by interface name | Wireless Extensions ioctls, **blind** &mdash; fuzzes the **host kernel driver** |

The USB targets drive the dongle directly through usbfs and need no kernel
module. The kernel-shim targets reach a command ring that lives in
kernel/device memory (unreachable from userspace) by injecting through the
in-kernel driver &mdash; see [Fuzzing a shim-backed NIC](#fuzzing-a-shim-backed-nic).
The `usb-generic` target is the fallback for a USB NIC that maps to none of the
class-directed targets &mdash; see
[Blind-fuzzing a proprietary USB NIC](#blind-fuzzing-a-proprietary-usb-nic).
The `wext-generic` target fuzzes a legacy Wireless Extensions driver's ioctl
handlers &mdash; note this exercises the **host kernel**, not device firmware
&mdash; see [Blind-fuzzing a WEXT driver](#blind-fuzzing-a-wext-driver).

## Listing NICs (`wlan list`)

Before fuzzing, enumerate the wireless NICs on the host and see which target
(if any) supports each. `wlan list` reads sysfs only &mdash; no hardware access,
no kernel module, no privileges:

```sh
embedded_linux_audit linux wlan list
```

```text
INTERFACE    PHY    DRIVER           BUS   USBID      DETECT   FUZZER TARGET  TRANSPORT
wlan0        phy0   ath11k_pci       pci   -          phy80211 ath11k         ela_kmod shim
wlan1        phy1   rtl8xxxu         usb   0bda:8179  phy80211 rtl8xxxu       usbfs
wlo1         phy2   iwlwifi          pci   -          phy80211 (unsupported)  -
wlan2        phy3   (proprietary)    usb   0e8d:7612  phy80211 (unsupported)  -
ra0          -      rt2860v2         soc   -          wext     (unsupported)  -
ath0         -      qca_wmac         soc   -          name?    (unsupported)  -

6 WLAN interface(s) (1 name-only guess(es), no kernel wireless marker), 2 fuzzable with `linux wlan fuzz --target <name>`.

1 USB NIC(s) with no class-directed target -- blind-fuzz with `--target usb-generic` (shallow coverage):
  wlan2        linux wlan fuzz --target usb-generic --usb-id 0e8d:7612

1 WEXT NIC(s) with no class-directed target -- blind-fuzz the driver ioctls with `--target wext-generic` (root; can panic the host):
  ra0          sudo linux wlan fuzz --target wext-generic --iface ra0
```

The `USBID` column shows the USB `VID:PID` for every NIC on the USB bus (`-` for
PCIe/SDIO/SoC radios), so the id needed by `--target usb-generic --usb-id` is
visible directly in the table.

An interface is listed when any kernel wireless marker identifies it &mdash; a
`phy80211` link, a `wireless/` sysfs dir, a `/proc/net/wireless` row, or
`DEVTYPE=wlan` in its `uevent` &mdash; and, failing all of those, when its name
matches a wireless pattern (`wlan*`, `wlp*`, `wlx*`, `wifi*`, `ath*`, `ra*`,
`mlan*`). The `DETECT` column names the signal that matched; `name?` flags a
name-only guess, the fallback for proprietary/vendor stacks (Aruba, some SoC
radios) that register no cfg80211/WEXT node. The bound driver comes from the
`device/driver` symlink, or `DRIVER=` in `device/uevent` when that symlink is
absent; the driver and bus map to a fuzzer target. `TRANSPORT` shows how that
target reaches the device (`usbfs` for USB dongles, `ela_kmod shim` for the
PCIe/SDIO targets). `(unsupported)` means no target covers that driver yet.

Any listed NIC on the **USB** bus with no class-directed target is still
reachable for a blind sweep, so `wlan list` follows the table with a
copy-pasteable `--target usb-generic --usb-id <VID:PID>` line for each (the
VID:PID read from the parent USB device in sysfs). PCIe/SoC NICs with no target
get no such hint &mdash; there is no userspace command transport to reach them.

## Options

| Option | Default | Description |
|---|---|---|
| `--target <name>` | (required) | NIC target from the table above |
| `--iterations <N>` | `100000` | Number of cases to run |
| `--probe-every <N>` | `8` | Liveness-probe interval, in cases |
| `--seed <N>` | `1234` | RNG seed; the same seed replays the same case stream |
| `--out <dir>` | `crashes` | Directory for crash artifacts |
| `--fw <path>` | &mdash; | Firmware image (target-specific; unused by most targets) |
| `--usb-id <V:P>` | &mdash; | `usb-generic` only: target USB device by hex VID:PID (e.g. `0bda:8179`; product `*` or omitted = match any) |
| `--iface <name>` | &mdash; | `wext-generic` only: network interface to fuzz (e.g. `wlan0`) |
| `--replay <file>` | &mdash; | Reproduce a saved crash on hardware instead of fuzzing |
| `--show <file>` | &mdash; | Decode a crash file into a readable command/field breakdown for triage (offline, no hardware) |
| `--selftest` | &mdash; | Run the offline engine self-tests (no hardware) |

For `--replay` and `--show`, `--target` is optional: it is read from the crash
file's `# target=` header (an explicit `--target` still wins).

The global `--output-format` flag has no effect here; the command emits
progress text and writes crash files.

## Fuzzing a shim-backed NIC

The shim targets (`ath10k`, `ath11k`, `ath12k`, `mt76`, `brcmfmac`) inject
firmware commands into the running firmware through the `ela_kmod` kernel shim.
The shim installs a kprobe on the driver's command-send function, captures the
live driver context from the driver's own firmware traffic, and calls that
function with the fuzzer's command buffer. A second kprobe on the driver's
firmware-restart/crash entry counts firmware crashes &mdash; that counter is
the liveness oracle. Each target names its own send/restart symbols and command
grammar:

| Target | Send symbol | Crash oracle | Command grammar |
|---|---|---|---|
| `ath10k` | `ath10k_wmi_cmd_send` | `ath10k_core_restart` | WMI |
| `ath11k` | `ath11k_wmi_cmd_send` | `ath11k_core_restart` | WMI-TLV |
| `ath12k` | `ath12k_wmi_cmd_send` | `ath12k_core_restart` | WMI-TLV |
| `mt76` | `mt76_mcu_send_and_get_msg` | `mt79xx/mt76xx_mac_reset_work` | connac MCU (station/wtbl TLVs) |
| `brcmfmac` | `brcmf_fil_cmd_data_set` | `brcmf_fw_crashed` | BCDC firmware ioctls |

The ath WMI-TLV targets prepend a `tlv_header` word `(tag << 16) | length` to
each command and set the correct tag/length on send so fuzzed fields reach the
handler (their `RAW_TLV` case leaves it fuzzed to hit the TLV parser). `mt76`
fuzzes the station/wtbl request headers' fixed-array index fields plus a
trailing MCU TLV. `brcmfmac` fuzzes the `_le` ioctl structs whose length/count
fields firmware trusts against fixed buffers (key length vs key buffer, SSID
length, scan counts). The walkthrough below uses `ath10k`; substitute any shim
target's name and its driver.

### Prerequisites

1. **A kernel with `CONFIG_KPROBES`** (standard on distro kernels). Without it
   the shim ioctls return `EOPNOTSUPP`.
2. **Build and load `ela_kmod`** against the running kernel's headers (see
   [Kernel-Backed Hardware Commands](../kernel-hardware.md) for details):

   ```sh
   make -C kmod
   sudo insmod kmod/ela_kmod.ko
   ```

3. **The `ath10k` driver bound and the interface generating WMI traffic.** The
   shim can only capture the driver context once the driver sends a firmware
   command, so the interface must be active. Bringing it up and running a scan
   is enough:

   ```sh
   sudo ip link set wlan0 up
   sudo iw dev wlan0 scan &        # generates WMI traffic for capture
   ```

4. **Run as root** (the shim device is mode `0600` and requires
   `CAP_SYS_RAWIO`).

### Run

```sh
sudo ./embedded_linux_audit linux wlan fuzz --target ath10k --out crashes/
```

On start the target waits for the driver context to be captured:

```text
[*] waiting for ath10k WMI traffic to capture driver context...
    (bring the interface up or trigger a scan to generate it)
[*] ath10k context captured; injecting WMI commands
[*] fuzzing ath10k for 100000 cases (probe every 8)
```

If no WMI traffic appears within the capture window, attach fails with
`[!] no WMI traffic captured; is the interface up?` &mdash; keep the interface
active (a periodic scan works well) and retry.

When ath10k firmware crashes it triggers a driver-level restart; the fuzzer
observes the restart, minimizes the responsible sequence, saves it, waits for
the driver to re-initialize (which re-captures the context automatically), and
continues.

## Blind-fuzzing a proprietary USB NIC

When `wlan list` shows a USB interface whose driver maps to no class-directed
target &mdash; a proprietary or simply not-yet-modeled dongle &mdash; the
`usb-generic` target can still exercise it. Take the VID:PID from the hint
`wlan list` prints (or from `lsusb`) and pass it with `--usb-id`:

```sh
sudo ./embedded_linux_audit linux wlan fuzz --target usb-generic --usb-id 0e8d:7612
```

This target has **no firmware command grammar**. Rather than mutating known
command fields, it structurally fuzzes the USB transport itself &mdash; the
`bRequest`/`wValue`/`wIndex` and payload length of vendor control transfers, and
bulk-OUT writes to data endpoints. Coverage is therefore far shallower than a
class-directed target: it will not know the device's command framing, so most
traffic is rejected at the transport layer. It is a first-look tool for hardware
the fuzzer has no model of, not a substitute for a real target.

Because a blind sweep provokes STALLs and endpoint errors constantly, those are
**not** treated as firmware death. Liveness is judged out-of-band by a standard
`GET_DESCRIPTOR` probe on endpoint 0, which a healthy device always answers; a
device that stops answering (or vanishes from the bus) is the crash signal, and
recovery waits for it to re-enumerate exactly as the other USB targets do.

Crash files record `target=usb-generic`, so `--replay` reproduces them &mdash;
but replay still needs `--usb-id` (the VID:PID is not stored in the crash file).
`--show` decodes a `usb-generic` crash offline without a device or `--usb-id`.

**Scope:** USB only. A proprietary **PCIe or SoC** radio exposes no userspace
command transport, and its driver's internal symbols are unknown to the
`ela_kmod` shim (which hooks named send functions), so there is no way to reach
its firmware command interface blindly. Those NICs get no `usb-generic` hint in
`wlan list`.

## Blind-fuzzing a WEXT driver

Interfaces `wlan list` marks `DETECT=wext` expose the legacy **Wireless
Extensions** ioctl API but map to no class-directed firmware target. The
`wext-generic` target fuzzes those ioctl handlers, addressed by interface name:

```sh
sudo ./embedded_linux_audit linux wlan fuzz --target wext-generic --iface ra0
```

> **This targets the HOST KERNEL, not device firmware.** It issues fuzzed
> `SIOCSIWxxx` ioctls over an `AF_INET` socket straight into the driver's WEXT
> handlers. A handler bug is a **kernel** bug &mdash; it can oops or **panic the
> host**, which no userspace recovery can undo (unlike a firmware crash, which
> only resets the RAM-resident radio). Treat this like the `ela_kmod` shim
> targets, and more so. SET ioctls require `CAP_NET_ADMIN`, so run as root.

It is semi-blind: the WEXT ioctl ABI *is* the grammar, so the fuzzer knows the
ioctl shapes (an essid/key/IE buffer with a length, a channel/rate/power param,
a BSSID) but not the device's semantics. The prime bug surface is the
length-bearing `iw_point` ioctls (`SIWESSID`, `SIWENCODE`, `SIWENCODEEXT`,
`SIWGENIE`, `SIWMLME`) whose length the driver trusts against a fixed buffer;
the engine drives that length across the boundaries. Parameter ioctls
(`SIWFREQ`, `SIWRATE`, `SIWTXPOW`, `SIWAUTH`, …) fuzz the integer values.

Liveness is judged by `SIOCGIWNAME` (a harmless GET any live interface
answers); expected per-ioctl rejections (`EPERM`/`EINVAL`/`E2BIG`/`EOPNOTSUPP`)
are not treated as death. Recovery only reopens the socket and re-probes &mdash;
a genuine kernel panic leaves nothing to recover, so run this where a host crash
is acceptable (a test device, not a bastion). Crash files record
`target=wext-generic`; `--replay` needs `--iface`, and `--show` decodes offline
without one.

### Remote crash capture

Set `--output-http` (the same option the `linux pcap` stream uses) and the
fuzzer uploads crashes to the agent API. This has two parts, described in detail
[below](#how-results-are-reported): **confirmed crashes are uploaded live for
any target**, and the host-kernel targets add a **panic dead-man's-switch**.

Because a WEXT bug can hard-panic the host, the agent may die before it can even
write the offending case locally &mdash; the on-device triage is lost with the
machine. So `wext-generic` streams each payload to the agent API **before**
executing it:

```sh
sudo ./embedded_linux_audit --output-http https://ela.example.com \
    linux wlan fuzz --target wext-generic --iface wlan0
```

There are two ways a crash reaches the API:

1. **Confirmed crashes (all targets).** Whenever the fuzzer's oracle detects a
   crash and the triage loop saves a minimized crash file locally, it also
   uploads that complete crash file to the API immediately (an `X` frame). This
   works for **any** target &mdash; not just the host-panic ones &mdash; and is
   the normal path for firmware crashes the agent survives. Just set
   `--output-http`; no other flag is needed.
2. **Host-panic capture (host-kernel targets).** The targets that run in the
   host kernel *additionally* stream every payload before it executes:
   `wext-generic` (driver ioctls) and the **`ela_kmod`-shim targets**
   (`ath10k`/`ath11k`/`ath12k`/`mt76`/`brcmfmac` &mdash; the inject runs in
   kernel context), matching the ethernet firmware and Bluetooth targets. (The
   usbfs targets drive the device from userspace, so they get crash upload only.)
   The API holds only the latest streamed payload; if the host panics and the
   agent dies before triage can run, the socket drops without the "done" marker
   and the API writes that last payload out as a `_panic` crash file.

Either way the artifact lands under the device's data directory
(`<data>/<mac>/wlan-fuzz/crash_*.txt`) and in the `uploads` table, exactly like a
captured pcap &mdash; a normal, replayable crash file (`# target=...` + case
lines). Fetch it and reproduce with `wlan fuzz --replay` (or decode offline with
`--show`).

Add `--insecure` to skip TLS verification against a self-signed endpoint. If no
`--output-http` is set, fuzzing proceeds with local-only triage and a warning.
This needs the API's `/wlan-fuzz/` WebSocket route (agent-api service + nginx);
it ships with the stack.

## How results are reported

All targets report through the same progress stream on stdout. Lines are
prefixed by a severity marker: `[*]` status, `[+]` a saved result, `[!]` a
firmware death or warning.

```text
[*] fuzzing ath10k for 100000 cases (probe every 8)
[*] 8000 cases, 0 crashes, 0 recoveries
[!] firmware dead after case 8123 (VDEV_INSTALL_KEY key_len=cnt:255)
[*] triage: replaying window of 8 case(s)
[*] window alone does not reproduce -- retrying with 32-case history prefix
[*] triage: reduced to 3 case(s)
[+] crash saved: crashes/crash_0001_min.txt (3 case(s))
[*] 16000 cases, 1 crashes, 3 recoveries
...
[*] done: 100000 cases, 1 crashes
```

- **Progress counters** print roughly every 10 seconds:
  `[*] <cases> cases, <crashes> crashes, <recoveries> recoveries`.
- **A firmware death** prints `[!] firmware dead after case <N> (<MSG> <note>)`,
  where `<MSG>` is the command name and `<note>` records which field was
  mutated and how (for example `key_len=cnt:255` means the `key_len` count
  field was set to 255, `vdev_id=idx:8` an index field set to 8).
- **Triage** then replays the window since the last good liveness probe on a
  fresh session, optionally prepends bounded history for sequence-dependent
  bugs, and binary-searches the shortest reproducing suffix:
  `[*] triage: reduced to <N> case(s)`.
- **A saved crash** prints `[+] crash saved: <path> (<N> case(s))`. The tag in
  the filename is `min` for a minimized sequence or `flaky` if it could not be
  reproduced deterministically.

### Crash artifacts

Crash files are plain text, one case per line, and are self-contained for
replay. The first line records the target and case count; each following line
is `<MSGNAME> <hex-payload> #<note>`:

```text
# target=ath10k cases=3
VDEV_CREATE 000000000200000000000000000000000000 #vdev_id=idx:0
PEER_CREATE 00000000000000000000000000000000 #
VDEV_INSTALL_KEY 0000...ff000000 #key_len=cnt:255
```

Because the format is greppable and hand-editable, you can trim or tweak a
case and re-run it. The default output directory is `/tmp/ela-crashes/`; pass
`--out DIR` to write somewhere else (a relative `--out crashes/`, as the
examples above use, lands under the current working directory).

### Exit status

- `0` &mdash; the run completed (fuzzing finished, or `--replay` reproduced the
  crash, or `--selftest` passed).
- `1` &mdash; attach failed (no device, module not loaded, no capture), or a
  `--replay` did not reproduce.
- `2` &mdash; a usage error (unknown target, missing `--target`, bad option).

## Triaging a finding

A crash file is self-contained: it records the target and the exact command
sequence, so a finding can be handed to someone who does not have the NIC.

### Read it offline with `--show`

`--show` decodes a crash file into a human-readable breakdown with no hardware
and no kernel module &mdash; the first step in triaging a report. Each command
is decoded field by field, the trust-boundary fields are tagged
`[INDEX]`/`[LENGTH]`/`[COUNT]`/`[ARRAY]`, and the mutation note records exactly
what was injected:

```sh
./embedded_linux_audit linux wlan fuzz --show crashes/crash_0001_min.txt
```

```text
# crash file crashes/crash_0001_min.txt decoded as target=ath11k

case 1: VDEV_CREATE (40 bytes)
    mutations: vdev_id=idx:16 num_cfg_txrx_streams=cnt:4
    tlv_header           = 0x00000000 (0)
    vdev_id              = 0x00000010 (16)  [INDEX]
    vdev_type            = 0x00000002 (2)
    ...
    num_cfg_txrx_streams = 0x00000004 (4)  [COUNT]

[*] 1 case(s). Reproduce on hardware with: --replay crashes/crash_0001_min.txt
```

Scalar fields decode exactly; a variable-length bytes field is shown as raw
hex and any bytes past the fixed struct are reported as trailing bytes. The
mutation note is authoritative for which field was edited and how.

### Reproduce it on hardware with `--replay`

```sh
sudo ./embedded_linux_audit linux wlan fuzz --replay crashes/crash_0001_min.txt
```

```text
[*] replaying 3 case(s) from crashes/crash_0001_min.txt
[+] replay reproduces
```

`[+] replay reproduces` (exit `0`) confirms the sequence still kills the
firmware; `[!] replay did not reproduce` (exit `1`) indicates a flaky or
state-dependent case. A whole campaign is reproducible by re-using its
`--seed` and `--iterations`.

## Offline self-test

The mutation engine, renderer, and triage loop can be validated without any
hardware. This also confirms that each target's command grammar renders to the
exact wire sizes of the driver structs it was extracted from:

```sh
./embedded_linux_audit linux wlan fuzz --selftest
```

```text
OK: ath9k-htc render sizes
OK: carl9170 render sizes
OK: ath10k render sizes
OK: rtl8xxxu box sizes (<=8)
OK: all audit bug-class triggers generated
OK: fuzz loop found planted sequence bug (29 crash files, expect >=1, all *_min)
SELFTEST PASSED
```

## Oracle and limitations

- **The oracle only sees crashes and hangs.** Out-of-bounds writes into
  tolerant firmware memory that neither crash nor reset survive undetected.
- **`ath10k` command-id numbering is firmware-ABI-specific.** The grammar uses
  the "main" WMI command map; 10.x/TLV firmware renumbers commands. The shim
  reports the driver's observed command ids so an operator can recalibrate;
  the field classes that get fuzzed are stable across ABIs.
- **Do not unload the ath10k driver mid-run.** The shim holds a captured
  pointer into the driver's private state.
- **`ath10k` triage cannot force a fresh firmware between replays** (only a
  real crash resets it), so minimization is coarser than for the USB targets.
  Saved artifacts still replay.
- **Throughput is device-bound.** Class-directed generation is what makes the
  budget effective: nearly every case is a plausible near-boundary command
  rather than noise.
