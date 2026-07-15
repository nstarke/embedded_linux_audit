# `embedded_linux_audit linux eth` Command

Ethernet NIC tooling, the counterpart of [`linux wlan`](wlan-fuzz.md). `eth
list` enumerates the host's ethernet NICs and reports which `eth fuzz` target
supports each; `eth fuzz` is a class-directed black-box fuzzer for ethernet NIC
command interfaces. It shares the NIC-fuzz engine (grammar model, class-directed
mutation, triage loop, remote crash stream) with the WLAN fuzzer.

> **Authorized use only.** Run this against your own hardware. Every target
> exercises the host driver or device firmware by design and can wedge or panic
> the host.

## How ethernet differs from WLAN

WLAN NICs expose a rich host→firmware command grammar (WMI, mailboxes), so nearly
every one is class-directed-fuzzable. **Most ethernet NICs do not** — an
e1000/igb/r8169/tg3 is driven by descriptor rings and MMIO, with no firmware
command mailbox. So the ethernet fuzzer splits into two surfaces:

- **`ethtool-generic`** — the broad blind target: fuzzes the driver's
  `SIOCETHTOOL` ioctl handlers over an `AF_INET` socket, by interface name.
  Works on *any* NIC. This is the ethernet sibling of `wext-generic`.
- **Firmware-mailbox targets** (`bnxt`, `i40e`, `ice`, `cxgb4`, `mlx5`) — the
  subset of NICs with a firmware command / admin-queue interface, injected
  through the `ela_kmod` kernel shim (same mechanism as the `ath10k`/`mt76` WLAN
  shim targets).

## Targets

| Target | Device | Interface | Transport |
|---|---|---|---|
| `ethtool-generic` | Any NIC, by interface name | `SIOCETHTOOL` ioctls | AF_INET socket, **blind** — fuzzes the **host kernel driver** |
| `bnxt` | Broadcom NetXtreme | HWRM commands | `ela_kmod` shim |
| `i40e` | Intel 700-series | Admin Queue | `ela_kmod` shim |
| `ice` | Intel E800-series | Admin Queue | `ela_kmod` shim |
| `cxgb4` | Chelsio T4/T5/T6 | FW_CMD mailbox | `ela_kmod` shim |
| `mlx5` | Mellanox ConnectX | cmdif | `ela_kmod` shim |

## Listing NICs (`eth list`)

```sh
embedded_linux_audit linux eth list
```

```text
INTERFACE    DRIVER         BUS   FUZZER TARGET    TRANSPORT
enp1s0f0     bnxt_en        pci   bnxt             ela_kmod shim
enp3s0       i40e           pci   i40e             ela_kmod shim
eth0         r8169          pci   ethtool-generic  ethtool ioctl

3 ethernet NIC(s), 2 with a class-directed firmware target; every NIC is also fuzzable blind with `--target ethtool-generic --iface <name>`.
```

`eth list` reads sysfs only. It shows physical ethernet NICs (ARPHRD_ETHER with
a backing device), excluding loopback, virtual interfaces (veth/bridge/bond/tun),
and wireless radios (those belong to [`wlan list`](wlan-fuzz.md)). A NIC whose
driver has a firmware command interface shows that target; every other NIC shows
`ethtool-generic`.

## `ethtool-generic` — blind ioctl fuzzing

```sh
sudo ./embedded_linux_audit linux eth fuzz --target ethtool-generic --iface eth0
```

> **This targets the HOST KERNEL driver, not device firmware** — a handler bug
> can oops or **panic the host**. SET ops need `CAP_NET_ADMIN` (run as root).

It drives the read-path ops that take a device offset/length the driver must
bound-check (`GEEPROM`/`GMODULEEEPROM`/`GREGS` — the classic "driver trusts a
length against a fixed buffer" class) and the non-persistent SET ops whose
counts/params the driver validates (`SRINGPARAM`, `SCHANNELS`, `SPAUSEPARAM`,
`SMSGLVL`, `TEST`, `PHYS_ID`). Liveness is judged by the unprivileged
`ETHTOOL_GLINK`; expected per-op errors (`EPERM`/`EINVAL`/`EOPNOTSUPP`/`EFAULT`)
are not treated as death.

> **Persistent writes are deliberately excluded.** `SEEPROM`/`SFLASH` and other
> ops that write the NIC's EEPROM or flash could brick it permanently, so they
> are not in the grammar.

Because it can panic the host, `ethtool-generic` supports the same **remote
crash capture** as `wext-generic`: with `--output-http` set, each payload is
streamed to the agent API (`/eth-fuzz/` endpoint) before execution, and a host
panic leaves the last one saved as a replayable crash file. Add `--insecure` for
a self-signed endpoint. See the WLAN doc's [remote crash
capture](wlan-fuzz.md#remote-crash-capture-survives-a-host-panic) section — the
mechanism is identical.

## Firmware-mailbox targets (`ela_kmod` shim)

`bnxt`/`i40e`/`ice`/`cxgb4`/`mlx5` inject fuzzed firmware commands through the
`ela_kmod` shim, which kprobes the driver's command-send symbol, captures the
live driver context from the driver's own traffic, and re-calls it with the
fuzzed command. A second kprobe on the driver's reset/error entry counts
firmware crashes — the liveness oracle. This is the same flow as the WLAN shim
targets; see [Fuzzing a shim-backed NIC](wlan-fuzz.md#fuzzing-a-shim-backed-nic)
for prerequisites (build/load `ela_kmod`, bring the interface up so the shim can
capture context, run as root).

| Target | Kprobed send symbol | Command interface |
|---|---|---|
| `bnxt` | `bnxt_hwrm_do_send_msg` | HWRM (little-endian) |
| `i40e` | `i40e_asq_send_command` | Admin Queue descriptor + buffer (little-endian) |
| `ice` | `ice_sq_send_cmd` | Admin Queue descriptor + buffer (little-endian) |
| `cxgb4` | `t4_wr_mbox_meat_timeout` | FW_CMD mailbox (big-endian) |
| `mlx5` | `mlx5_cmd_exec` | cmdif (big-endian) |

```sh
sudo ./embedded_linux_audit linux eth fuzz --target i40e --out crashes/
```

### Status, caveats, and version-fragility

- **Verified offline only.** These targets are structurally validated (the shim
  and grammars build and render; the ABI is locked by a unit test) but were not
  run against live hardware. The live inject paths mirror each driver's send
  signature but are unrun.
- **Representative v1 grammars.** Each grammar sweeps the command opcode/req_type
  and drives the length/count fields the firmware trusts, rather than modelling
  every command struct. The field *classes* (swept command id, length-bearing
  body) are the stable bug surface across firmware ABI versions even as
  individual command layouts and numbers shift.
- **`bnxt` needs a pre-5.12 kernel.** It hooks the `bnxt_hwrm_do_send_msg`
  symbol, which older kernels expose. Newer kernels refactored HWRM so the
  request rides a DMA buffer rather than a send argument; there the kprobe symbol
  is absent and attach fails cleanly.
- **`i40e`/`ice`/`cxgb4`/`mlx5`** hook a send function that takes the command
  buffer + length directly, which is stable across more kernel versions;
  `ice`/`cxgb4` additionally capture the control queue / mailbox number.
- Injecting crashes device firmware **and can panic the host kernel** (the inject
  runs in kernel context). Run only where a host crash is acceptable.

## Crash artifacts and triage

Identical to the WLAN fuzzer: crashes are self-contained text files (`# target=`
header + one hex case per line), reproducible with `--replay` and decodable
offline with `--show`. See [How results are
reported](wlan-fuzz.md#how-results-are-reported).
