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
