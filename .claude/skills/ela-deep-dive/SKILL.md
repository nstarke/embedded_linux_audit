---
name: ela-deep-dive
description: Deep analysis of a target through the client API — kick off Ghidra rootfs decompilation jobs, review decompiled C output, list live gdbserver sessions, attach GDB to running processes, and pull firmware dumps (SPI/NAND/eMMC/option ROM) for offline analysis. Use when the user wants to reverse a binary, root-cause a crash, debug a process on-device, or extract firmware.
---

# ELA deep dive — decompilation, debugging, firmware extraction

Uses the standard client API preflight (see ela-fleet). These are the
expensive analysis paths; run them against targets that /ela-triage or
/ela-fuzz flagged, not speculatively across a fleet.

## Ghidra rootfs decompilation

Pulls the device rootfs (`linux remote-copy --analysis-only --recursive /`)
and decompiles every ELF with Ghidra, server-side.

```sh
# start (202 with job record); device must be connected and will be BUSY for
# the duration of the copy — possibly an hour — during which other exec/spawn
# calls to it 504. Warn the user before starting.
curl -s -X POST -H "Authorization: Bearer $ELA_CLIENT_KEY" \
  "$ELA_CLIENT_URL/devices/$MAC/ghidra-analysis"
# poll
curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" "$ELA_CLIENT_URL/ghidra-analysis/$ID"
# when done: list decompiled binaries (relative path + .c file count)
curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" "$ELA_CLIENT_URL/ghidra-analysis/$ID/outputs"
# fetch decompiled C for one binary
curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" -o /tmp/binary.zip \
  "$ELA_CLIENT_URL/ghidra-analysis/$ID/output.zip?binary=<relative-path-from-outputs>"
```

Job status shows `filesFound`/`filesAnalyzed` progress. Once you have the C
output locally, review it directly: prioritize network-facing daemons found
by netstat triage and setuid binaries from the SUID inventory. Look for
command construction (`system`, `popen`, `exec*` with tainted input), unsafe
copies (`strcpy`/`sprintf`/unbounded `memcpy`), hardcoded credentials/keys,
and custom crypto. Cross-reference fuzz crash addresses against the
decompiled functions.

## Live debugging (gdbserver)

```sh
# find the PID on-device (linux/exec): ps | grep <daemon>
# start a gdb stub (ela/spawn — self-daemonizing):
{"command":"linux gdbserver <PID> <PORT>"}
# or the tunnel variant that connects back through the server:
{"command":"linux gdbserver tunnel <PID> <URL>"}
# list active stubs and their attach handles:
curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" "$ELA_CLIENT_URL/gdb/sessions"
```

Sessions list `mac`, an attach handle (hexkey), and `operatorConnected`.
Connect from the workstation with `gdb-multiarch` → `target remote ...`
(direct to `<device-ip>:<PORT>`, or via the nginx `/gdb/` bridge for tunnel
sessions). Attaching pauses the process — confirm with the user before
attaching to anything production-critical.

## Firmware and ROM extraction

Requires `ela_kmod` on the device (deliver via `/ela-fuzz` step 2 /
`/devices/:mac/module-builds` if missing). Run via `ela/exec`, one at a time;
dumps of large flash go via `ela/spawn`:

```sh
{"command":"spi list"}            then  {"command":"spi dump /tmp/spi.bin 0"}
{"command":"nand flash list"}     then  {"command":"nand flash dump /tmp/nand.bin 0"}
{"command":"emmc list"}           then  {"command":"emmc dump /tmp/emmc.bin 0"}   # needs kernel >= 6.9
{"command":"orom list"}           then  {"command":"orom dump /tmp/orom.bin 0"}
```

Always run `list` first and pass an explicit index — bare `dump` refuses
ambiguous ties. Then exfiltrate to the server so it appears in uploads:

```sh
{"command":"linux remote-copy /tmp/spi.bin <ELA_API_URL>"}        # ela/exec
```

Fetch it back with `GET /uploads/<id>/raw` and analyze offline
(binwalk, strings, unsquashfs as appropriate for local tooling). Dumps left
in `/tmp` on the device should be deleted afterwards (`linux/exec`:
`rm /tmp/<dump>`) — note this cleanup in the report.

## Output

Report what was analyzed and the concrete security conclusions: vulnerable
code paths with file/function references into the decompiled output, debug
session findings, and firmware contents of interest (bootloader versions,
embedded keys, hidden partitions). Feed confirmed issues back into the
finding list from `/ela-triage`, and use `/ela-report` for the final
deliverable.
