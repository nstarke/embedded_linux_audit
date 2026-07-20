---
name: ela-fuzz
description: Orchestrate hardware-interface fuzzing campaigns (WLAN, ethernet, Bluetooth HCI, CPU instructions) on a connected ELA device via the client API, including ela_kmod delivery through the module-builds route, and collect crash artifacts. Use when the user asks to "fuzz" a device or interface, or to follow up on fuzz-crash findings. Destructive-adjacent — always confirm scope with the user first.
---

# ELA fuzz — hardware interface fuzzing campaigns

**Confirm before starting.** Fuzzing can hang NICs, wedge firmware, and crash
the target kernel. Ask the user to confirm (a) the device is in scope for
active testing, (b) it is acceptable for the device to need a power cycle,
and (c) which interface class to fuzz. Never fuzz a device that carries the
operator's own control channel connectivity unless the user explicitly
accepts losing the session.

Uses the standard client API preflight (see ela-fleet). Docs for flag details:
`docs/agent/linux/wlan-fuzz.md`, `eth-fuzz.md`, `bt-fuzz.md`, `cpu-fuzz.md`.

## 1. Enumerate targets (cheap, safe, via ela/exec)

```sh
# one at a time per device
{"command":"linux wlan list"}   # WLAN NICs and which fuzz target supports each
{"command":"linux eth list"}    # ethernet NICs
{"command":"linux bt list"}     # Bluetooth controllers
{"command":"linux cpu list"}    # ISA and applicable cpu-fuzz mode
```

Report what is fuzzable and with which target class. Driver-directed targets
(`ath10k/ath11k/ath12k/mt76/brcmfmac`, `bnxt/i40e/ice/cxgb4/mlx5`) require
`ela_kmod` loaded on the device; blind targets (`usb-generic`, `wext-generic`,
`ethtool-generic`, `hci-generic`, cpu fuzz) do not need it.

## 2. Deliver ela_kmod if needed (module-builds route)

Check whether the module is already loaded (`linux/exec`:
`grep ela_kmod /proc/modules`). If not, build a matching module server-side:

```sh
# create build from the device's kernel facts (autobuild refreshes buildinfo live)
curl -s -X POST -H "Authorization: Bearer $ELA_CLIENT_KEY" -H 'Content-Type: application/json' \
  -d '{"autobuild":true}' "$ELA_CLIENT_URL/devices/$MAC/module-builds"
# poll status until "succeeded" (also lists vermagic result)
curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" "$ELA_CLIENT_URL/module-builds/$ID"
# push the .ko to the device and insmod it
curl -s -X POST -H "Authorization: Bearer $ELA_CLIENT_KEY" -H 'Content-Type: application/json' \
  -d '{}' "$ELA_CLIENT_URL/module-builds/$ID/deliver"
```

`409` on create = no buildinfo upload (pass `autobuild:true`); `422` = no
cross toolchain for that ISA; `200` with `reused:true` = an identical build
already existed. Delivery handles vermagic-reject retries automatically.

## 3. Run the campaign

Set up crash collection first, then fuzz. Fuzz runs are long: use
**`POST /terminal/:mac/ela/spawn`** (self-daemonizing), not exec. While a
spawned ELA command holds the shell, other exec calls to that MAC will 504 —
issue the coredump/config steps *before* the fuzz spawn.

```sh
# 1. enable coredump capture, POSTing cores to the server
{"command":"linux coredump --output-http <ELA_API_URL>"}          # ela/exec
# 2. start the fuzzer with result upload (examples; see per-fuzzer docs for flags)
{"command":"linux cpu fuzz --iterations 100000"}                  # ela/spawn
{"command":"linux wlan fuzz --target ath10k --interface wlan0"}   # ela/spawn
{"command":"linux eth fuzz --target ethtool-generic --interface eth0"}
{"command":"linux bt fuzz --target hci-generic --index 0"}
```

The fuzzers upload structured results (`wlan-fuzz`, `eth-fuzz`, `bt-fuzz`,
`cpu-fuzz` types) when `--output-http`/`ELA_API_URL` is configured; without
it they run local-only with a warning — verify results are landing by
polling `GET /uploads` counts early in the run.

## 4. Monitor

Poll on an interval (do not hammer):
- `GET /terminal/sessions` — is the device still alive? A dropped session
  during fuzzing is itself a result (possible kernel panic) — record the
  timestamp and last artifacts.
- `GET /uploads?type=<class>-fuzz&limit=5` and `GET /uploads?type=coredump&limit=5` —
  new crash records.
- Once the shell is free, `ela/exec` `linux dmesg` to capture oops traces.

## 5. Wrap up

Kill leftover tracked spawns (`DELETE /terminal/:mac/spawn/:pid`). Fetch each
crash artifact (`GET /uploads/<id>` and `/raw` for cores). Report:
targets fuzzed, iterations/duration, crashes and anomalies with artifact ids,
device health at end, and reproduction commands. Recommend `/ela-deep-dive`
(gdbserver + Ghidra) for any crash worth root-causing.
