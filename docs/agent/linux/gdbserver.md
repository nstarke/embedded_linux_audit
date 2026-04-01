# `embedded_linux_audit linux gdbserver` Command

Attaches to a running process by PID and exposes a GDB Remote Serial Protocol (RSP) server on a TCP port. A GDB client (e.g. `gdb-multiarch`) can then connect to inspect and control the target process remotely.

The command forks to the background immediately after a successful `ptrace` attach. The foreground process exits once the server is ready, printing the connection address to stderr.

## `gdbserver` arguments

- `<PID>` — required process ID to attach to
- `<PORT>` — required TCP port number (1–65535) on which to listen for an incoming GDB connection

There are no `--output-format`, `--output-tcp`, or `--output-http` options for this command; all interaction happens over the GDB RSP connection.

## Supported GDB RSP features

The server advertises the following capabilities in its `qSupported` response:

| Feature | Description |
|---|---|
| `qXfer:exec-file:read` | Returns the executable path of the attached process |
| `qXfer:auxv:read` | Returns the auxiliary vector from `/proc/<pid>/auxv` |
| `qXfer:features:read` | Returns `target.xml` describing registers for the target architecture |
| `qXfer:libraries-svr4:read` | Returns the SVR4 shared-library list from `/proc/<pid>/maps` |
| `qXfer:threads:read` | Returns a thread list built from `/proc/<pid>/task/` |
| `qXfer:memory-map:read` | Returns a GDB memory map built from `/proc/<pid>/maps` |
| `qXfer:siginfo:read` | Returns raw `siginfo_t` for the stopped thread |
| `vAttach` | Re-attach to a different PID mid-session |
| `vCont;c;C;s;S` | Continue, continue-with-signal, single-step, step-with-signal |
| `hwbreak` | Hardware breakpoints via x86_64 debug registers |
| `Z1`–`Z4` | Hardware watchpoints (write, read/write) via DR0–DR3/DR7 on x86_64 |

Software breakpoints (`Z0`) are handled by writing an `INT3` (`0xcc`) byte into process memory via `ptrace`.

## Architecture support

`qXfer:features:read` returns a `target.xml` document describing the register file. Full per-register descriptions (24 registers) are provided for x86_64. All other architectures receive an `<architecture>` element only.

## Notes

- The agent must run as a user with permission to `ptrace` the target PID. On most Linux systems this requires running as root or having `CAP_SYS_PTRACE`, or the target process must be a descendant.
- Only one GDB client connection is served at a time. The server exits after the GDB session ends.
- `vAttach` detaches from the current process and attaches to a new PID without restarting the server.
- Syscall-entry stops are filtered with `PTRACE_O_TRACESYSGOOD` to prevent spurious `SIGTRAP` delivery to GDB.
- The TCP listener binds to `0.0.0.0` on the specified port.

## Examples

```bash
# Attach to PID 1234, listen on port 2345
./embedded_linux_audit linux gdbserver 1234 2345

# In gdb-multiarch (on the auditing host):
# (gdb) target remote <agent-ip>:2345
```

---

# `embedded_linux_audit linux gdbserver tunnel` Subcommand

Routes the GDB Remote Serial Protocol over WebSocket through the ELA GDB bridge API instead of opening a direct TCP port. This is useful when the target device is not directly reachable from the analyst workstation but can reach the ELA server.

The agent attaches to the process, generates a random 128-bit session key, and connects to `/gdb/in/<32-hex-key>` on the bridge. The analyst's GDB connects to `/gdb/out/<32-hex-key>` and the bridge relays binary frames bidirectionally.

## `gdbserver tunnel` arguments

- `<PID>` — required process ID to attach to
- `<WSS_BASE_URL>` — required base WebSocket URL of the ELA server (e.g. `wss://ela.example.com` or `ws://ela.example.com` for plain HTTP)
- `--insecure` — optional; disables TLS certificate verification when connecting to the bridge

## Session key

A 16-byte key is read from `/dev/urandom` and formatted as 32 lowercase hex characters. The agent prints the full `wss://` URLs to stderr after a successful attach:

```
GDB tunnel ready:
  in:  wss://ela.example.com/gdb/in/aabbccddeeff00112233445566778899
  out: wss://ela.example.com/gdb/out/aabbccddeeff00112233445566778899
Connect GDB with:
  wss-remote wss://ela.example.com/gdb/out/aabbccddeeff00112233445566778899
```

Copy the `out` URL and use it in `gdb-multiarch` on the analyst workstation.

## Connecting with `wss-remote`

`wss-remote` is a GDB Python command registered by `tools/gdb-ws-insecure.py`. It wraps `target remote` with WebSocket support and optional `Authorization` header injection.

### Installing `wss-remote` into `~/.gdbinit`

**Automatic** — `nginx/install.sh` appends the `source` line during setup:

```sh
./nginx/install.sh ela.example.com
```

**Manual** — from the repository root:

```sh
echo "source $(pwd)/tools/gdb-ws-insecure.py" >> ~/.gdbinit
```

After either method, `wss-remote` is available in every subsequent `gdb-multiarch` session.

You can also load it for a single session without modifying `~/.gdbinit`:

```
(gdb) source /path/to/tools/gdb-ws-insecure.py
```

### `wss-remote` usage

```
wss-remote [--insecure] [--token TOKEN] wss://HOST/gdb/out/<32-hex-key>
```

- Without `--insecure`: uses GDB's native WebSocket transport (requires GDB 14+ built with WebSocket support).
- With `--insecure`: falls back to the `tools/gdb-ws-proxy.py` stdin/stdout pipe with TLS verification disabled. Works with any GDB version that supports `target remote | command`.
- `--token TOKEN`: override the API bearer token. If omitted, `ELA_API_KEY` from the environment is used.

## Example workflow

```bash
# --- On the target device (via ela shell or terminal) ---
./embedded_linux_audit linux gdbserver tunnel --insecure 1234 wss://ela.example.com

# Agent prints:
#   GDB tunnel ready:
#     out: wss://ela.example.com/gdb/out/aabbccddeeff00112233445566778899
#   Connect GDB with:
#     wss-remote wss://ela.example.com/gdb/out/aabbccddeeff00112233445566778899

# --- On the analyst workstation ---
export ELA_API_KEY=<your-api-key>
gdb-multiarch ./firmware.elf
(gdb) wss-remote --insecure wss://ela.example.com/gdb/out/aabbccddeeff00112233445566778899
```

---

# Ghidra Bridge (`tools/ghidra_bridge.py`)

Opens a TCP server on localhost that relays raw GDB RSP bytes to and from the WebSocket tunnel. Ghidra's built-in GDB debugger (or any tool that speaks GDB remote over TCP) can connect to `localhost:<port>` without needing WebSocket support.

## How it works

```
Ghidra ──TCP──▶ ghidra_bridge.py ──WebSocket──▶ ELA bridge ──WebSocket──▶ agent gdbserver
```

Each incoming TCP connection opens a fresh WebSocket session to the `/gdb/out/<key>` endpoint. When either side closes, both the TCP and WebSocket connections are torn down. The bridge accepts one client at a time; reconnecting in Ghidra establishes a new session.

## Arguments

| Flag | Required | Default | Description |
|---|---|---|---|
| `--url URL` | yes | — | `wss://` or `ws://` URL of the `/gdb/out/<32-hex-key>` endpoint |
| `--port PORT` | no | `9999` | Local TCP port to listen on |
| `--insecure` | no | off | Disable TLS certificate verification |
| `--token TOKEN` | no | — | Bearer token for the `Authorization` header (falls back to `ELA_API_KEY` env var) |

## Dependencies

```
pip install websockets
```

The same `websockets` package used by `gdb-ws-proxy.py`.

## Example workflow

```bash
# --- On the target device ---
./embedded_linux_audit linux gdbserver tunnel --insecure 1234 wss://ela.example.com

# Agent prints:
#   GDB tunnel ready:
#     out: wss://ela.example.com/gdb/out/aabbccddeeff00112233445566778899

# --- On the analyst workstation ---
export ELA_API_KEY=<your-api-key>

# Start the bridge
python3 tools/ghidra_bridge.py \
    --url wss://ela.example.com/gdb/out/aabbccddeeff00112233445566778899 \
    --insecure

# Bridge output:
#   [ghidra_bridge] listening on 127.0.0.1:9999
#   [ghidra_bridge] websocket target: wss://ela.example.com/gdb/out/aabbcc...
#   [ghidra_bridge] waiting for Ghidra to connect ...
```

## Connecting from Ghidra

1. Open the **Debugger** tool (Window → Debugger).
2. Click **Connect** and choose the **gdb** connector.
3. In the GDB console that appears, run:

```
(gdb) set remotetimeout 30
(gdb) target remote localhost:9999
```

Ghidra will attach to the remote process through the bridge. All standard GDB remote features (register reads, memory reads, breakpoints, stepping) work normally.

## Using a custom port

If port 9999 is already in use, pick another port and adjust the `target remote` command accordingly:

```bash
python3 tools/ghidra_bridge.py \
    --url wss://ela.example.com/gdb/out/<key> \
    --port 12345

# In Ghidra's GDB console:
# (gdb) target remote localhost:12345
```

## Notes

- The bridge binds to `127.0.0.1` only; it is not accessible from other machines.
- Set `remotetimeout 30` in GDB/Ghidra to account for WebSocket relay latency, matching the recommendation for `wss-remote`.
- The bridge can also be used with standalone `gdb-multiarch` as an alternative to the pipe-based `gdb-ws-proxy.py` or `wss-remote` commands.
