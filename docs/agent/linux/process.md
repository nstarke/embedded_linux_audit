# `embedded_linux_audit linux process` Command

Monitors running processes for restart or PID-set changes. A background daemon polls `/proc` every 2 seconds; when the set of PIDs matching a watched needle changes, an event record is emitted to stdout, a TCP destination, or an HTTP(S) endpoint.

## Subcommands

### `watch on <needle>`

Register `<needle>` as a term to watch and ensure the background daemon is running. `<needle>` is matched as a substring against each process's full command line (the space-joined contents of `/proc/<pid>/cmdline`).

**Constraints on `<needle>`:**
- Non-empty, at most 128 bytes
- Must not contain newlines or tabs

If the daemon is not already running it is started automatically.

### `watch off <needle>`

Remove `<needle>` from the watch list. If no needles remain, the daemon is stopped automatically.

### `watch list`

Print the current watch list with live PID sets (scanned at the time of the call, not from daemon state). Output format is controlled by `--output-format`.

## Arguments and options

- `<needle>` — required for `watch on` and `watch off`; the command-line substring to match
- `--output-format <txt|csv|json>` — top-level global option controlling event and list output format (default: `txt`)
- `--output-tcp <IPv4:port>` — top-level global option to forward event output to a TCP destination
- `--output-http <http://host:port/path>` — top-level global option to POST event output to the helper API
- `--output-http <https://host:port/path>` — top-level global option to POST event output to the helper API over HTTPS
- `--insecure` — top-level global option to disable TLS certificate and hostname verification for HTTPS output

## Output formats

Each event record describes a PID-set change for one needle (old PIDs → new PIDs):

- `txt` — human-readable text: needle, old PIDs, new PIDs
- `csv` — one CSV row: `"<needle>","<old_pids>","<new_pids>"`
- `json` — one JSON object with `needle`, `old_pids`, and `new_pids` fields

The same format is used for `watch list` entries, except the fields are `needle` and `pids` (current live PIDs).

When HTTP(S) output is configured, the client POSTs to `/{mac_address}/upload/process_watch` using:

- `text/plain; charset=utf-8` for `txt`
- `text/csv; charset=utf-8` for `csv`
- `application/json; charset=utf-8` for `json`

## Runtime files

The daemon uses three files under `/tmp`:

| File | Purpose |
|---|---|
| `/tmp/ela-process-watch.state` | Persistent needle list (tab-separated `needle\tpids` lines) |
| `/tmp/ela-process-watch.pid` | PID of the running daemon process |
| `/tmp/ela-process-watch.lock` | Exclusive lock file coordinating daemon and CLI access |

## Notes

- The daemon is started with `fork()`+`setsid()` and runs independently of the calling terminal. Its stdout/stderr are redirected to `/dev/null`.
- A maximum of 64 needles may be watched simultaneously.
- The daemon re-reads the state file on every poll cycle so needles added or removed via `watch on`/`watch off` take effect within one poll interval (2 seconds).
- PID lists are sorted and comma-separated (e.g. `"123,456,789"`). An empty string means no matching processes were found.
- An event is emitted only when the PID set actually changes, not on every poll.

## Examples

```bash
# Start watching for any process whose command line contains "nginx"
./embedded_linux_audit linux process watch on nginx

# Watch for a specific binary path
./embedded_linux_audit linux process watch on /usr/sbin/sshd

# List all currently watched needles and their live PIDs
./embedded_linux_audit linux process watch list

# List in JSON format
./embedded_linux_audit --output-format json linux process watch list

# Stop watching for nginx
./embedded_linux_audit linux process watch off nginx

# Watch with JSON events forwarded to a remote collector
./embedded_linux_audit --output-format json --output-http http://192.168.1.50:5000 \
    linux process watch on init
```
