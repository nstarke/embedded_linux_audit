# `embedded_linux_audit linux bt` Command

Bluetooth controller tooling, the Bluetooth counterpart of [`linux
wlan`](wlan-fuzz.md) / [`linux eth`](eth-fuzz.md). `bt list` enumerates the
host's Bluetooth controllers; `bt fuzz` is a class-directed black-box fuzzer for
the host→controller **HCI command interface**. It shares the NIC-fuzz engine
(grammar model, class-directed mutation, triage loop, remote crash stream) with
the WLAN and ethernet fuzzers.

> **Authorized use only.** Run this against your own hardware. Fuzzing HCI
> commands exercises the kernel HCI layer, the driver, and the controller
> firmware by design and can wedge or panic the host.

## Why HCI

HCI (Host Controller Interface) is the standardized host→controller command
protocol — every Bluetooth controller speaks it. Unlike an ethernet NIC, a
Bluetooth controller *always* exposes a firmware command interface, and unlike
the ethernet firmware mailboxes it is reachable **directly from userspace** over
a raw HCI socket — no kernel shim needed. So there is a single, universal target:

- **`hci-generic`** — fuzzes HCI commands over a raw **HCI User Channel** socket,
  addressed by controller index (`hci0`, `hci1`, …). It is the Bluetooth sibling
  of `wext-generic`/`ethtool-generic`, but because HCI is a real command protocol
  (opcode + parameter-length + params) it is class-directed, not purely blind.

An HCI command packet is `opcode(2) + parameter_total_length(1) + params`. The
grammar drives the parameter-length byte the controller trusts against the
actual params, and the length bytes *inside* LE advertising/scan data
(`LE_Set_Advertising_Data` etc.) — the classic "firmware trusts a length against
a fixed buffer" class — across the standard, LE, and vendor (`0xFCxx`) opcode
space.

## Listing controllers (`bt list`)

```sh
embedded_linux_audit linux bt list
```

```text
CONTROLLER ADDRESS            BUS      FUZZER TARGET  TRANSPORT
hci0       AA:BB:CC:DD:EE:FF  usb      hci-generic    HCI User Channel

1 Bluetooth controller(s), fuzzable with `linux bt fuzz --target hci-generic --hci <name>`.
```

`bt list` reads `/sys/class/bluetooth` only (no hardware access). The address
column may show `?` without privilege.

## Fuzzing (`bt fuzz`)

```sh
# 1. Release the controller so the exclusive User Channel can bind:
sudo hciconfig hci0 down        # or: stop bluetoothd / rfkill block bluetooth
# 2. Fuzz it:
sudo ./embedded_linux_audit linux bt fuzz --target hci-generic --hci hci0
```

> **This traverses the HOST KERNEL** (HCI socket layer + driver) on the way to
> the controller firmware. A bug can crash the controller firmware **or oops /
> panic the host kernel**. It needs `CAP_NET_ADMIN` (run as root) and the
> controller **DOWN** — the User Channel is exclusive, so BlueZ must not be
> holding it (`hciconfig hciN down`, stop `bluetoothd`, or `rfkill block`). If
> the bind fails with `EBUSY`, that is why.

Liveness is judged out-of-band by `Read_BD_ADDR` (a harmless read any live
controller answers); a wedged controller stops responding. Recovery reopens the
User Channel and re-probes — a hard controller crash may need a replug.

### Remote crash capture

Because HCI fuzzing can panic the host, `hci-generic` streams each command to the
agent API for **remote crash capture**, exactly like the WLAN/ethernet host-kernel
targets: with `--output-http` set, each command is streamed (to the `/bt-fuzz/`
endpoint) before it is sent, so a host panic leaves the last one saved as a
replayable crash file. Add `--insecure` for a self-signed endpoint. See the WLAN
doc's [remote crash capture](wlan-fuzz.md#remote-crash-capture-survives-a-host-panic).

## Options

| Option | Default | Description |
|---|---|---|
| `--target hci-generic` | (required) | the only target today |
| `--hci <name>` | `hci0` | controller to fuzz (`hciN`) |
| `--iterations <N>` | `100000` | cases to run |
| `--probe-every <N>` | `8` | liveness-probe interval |
| `--seed <N>` | `1234` | RNG seed |
| `--out <dir>` | `crashes` | crash artifact directory |
| `--replay <file>` | — | reproduce a saved crash on hardware |
| `--show <file>` | — | decode a crash file offline for triage |
| `--insecure` | — | skip TLS verification for the remote-capture stream |
| `--selftest` | — | run the offline engine self-tests |

## Scope and status

- `hci-generic` covers the **host→controller HCI command** surface. Fuzzing the
  *receive* side — L2CAP/RFCOMM/SDP/SMP/ATT frame parsing — is a different
  mechanism (crafted inbound packets, needing a peer or a virtual controller) and
  is not built here; it would be a separate target.
- The live socket transport is **verified offline only** (grammar renders and the
  ABI builds; the User Channel path mirrors the kernel HCI socket API but was not
  run against a controller here), consistent with the other hardware targets.

## Crash artifacts and triage

Identical to the WLAN/ethernet fuzzers: self-contained text files (`# target=`
header + one hex case per line), reproducible with `--replay`, decodable offline
with `--show`. See [How results are reported](wlan-fuzz.md#how-results-are-reported).
