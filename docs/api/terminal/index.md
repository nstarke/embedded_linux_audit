# WebSocket Terminal Server (`api/terminal`)

The terminal server provides a browser-less, operator-facing interface for
managing multiple simultaneous agent connections.  Each agent that connects
via `transfer --remote ws://...` appears as a session.  The operator interacts
with the running sessions through a terminal TUI served on the machine running
the server.

## Requirements

- Node.js ≥ 18
- `express` and `ws` npm packages (`npm install` inside `api/terminal/`)

## Starting the server

### Development / manual

```sh
cd api/terminal
npm install          # first time only
npm start            # listen on port 8080, no authentication
```

The port can be overridden with the `ELA_TERMINAL_PORT` environment variable:

```sh
ELA_TERMINAL_PORT=9090 npm start
```

### Production (systemd)

The included `systemd/ela-terminal.service` unit runs the server inside a
named tmux session so that any user on the host can attach to the TUI without
restarting the service:

```sh
# Install and start
cp systemd/ela-terminal.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ela-terminal

# Attach to the TUI from any shell on the host
tmux -S /run/ela-terminal/tmux.sock attach -t ela-terminal
```

The tmux socket lives at `/run/ela-terminal/tmux.sock` and is created with
mode `0666` so all users can attach without `sudo`.

### Connecting to the tmux session

Once the service is running, any user on the host can attach to the live TUI
without restarting or reconfiguring the service:

```sh
tmux -S /run/ela-terminal/tmux.sock attach -t ela-terminal
```

#### Granting access — "access not allowed"

tmux uses `getpeereid()` on the Unix socket to verify that the connecting
client's UID matches the server's UID.  Because the server process runs as
the `ela` service account, any other user receives:

```
access not allowed
```

This is independent of socket or directory permissions.

The service uses `tmux server-access` (tmux ≥ 3.2) to grant access to every
member of the `ela` Unix group at startup.  To allow a user to attach, add
them to the group and restart the service:

```sh
sudo usermod -aG ela <username>
sudo systemctl restart ela-terminal
```

After that, `ela-attach` works without `sudo` for any member of the `ela`
group.

#### Detaching and re-attaching

To **detach** from the session and return to your shell without stopping the
server, press `Ctrl-b d` (the standard tmux detach key sequence), or type
`/detach` at the TUI prompt and press Enter.  Either method leaves the server
running and all agent connections intact.

If you close the terminal window or your SSH session drops, the tmux session
keeps running inside the service — simply re-attach with the command above.

To **list active tmux sessions** without attaching:

```sh
tmux -S /run/ela-terminal/tmux.sock list-sessions
```

### With API key enforcement

Start with `--validate-key` to require a bearer token on every incoming
WebSocket connection.  The server reads tokens from `api/ela.key` (one token
per line).  If the file is missing or empty the server prints an error and
exits.

```sh
npm run start:secure         # equivalent to: node server.js --validate-key
```

The agent must then supply a matching token:

```sh
./embedded_linux_audit \
    --api-key mysecrettoken \
    transfer --remote ws://server:8080
```

See [API Key Authentication — server side](../auth.md) for how to create and
manage `ela.key`.

## Agent connection

The agent connects using the `transfer --remote` subcommand:

```sh
# Plain WebSocket — direct to server (no nginx)
./embedded_linux_audit transfer --remote ws://server:8080

# Plain WebSocket — via nginx on port 80
./embedded_linux_audit transfer --remote ws://ela.example.com

# Secure WebSocket — via nginx on port 443
./embedded_linux_audit transfer --remote wss://ela.example.com

# Skip TLS certificate verification (self-signed certs, testing only)
./embedded_linux_audit --insecure transfer --remote wss://ela.example.com
```

The agent always appends `/terminal/<mac>` to the base URL before connecting.

The agent appends its MAC address to the URL path
(`/terminal/<mac>`), which the server uses as the session identifier.  If a
session already exists for that MAC the previous connection is closed and
replaced.

### Automatic reconnection

The agent automatically reconnects if the WebSocket connection drops.  The
default is 5 reconnect attempts, each after a 60-second wait.  Use
`--retry-attempts` to override:

```sh
# Retry up to 10 times before exiting
./embedded_linux_audit --remote ws://server:8080 --retry-attempts 10

# No retry — exit immediately on disconnect
./embedded_linux_audit --remote ws://server:8080 --retry-attempts 0

# Equivalent for the transfer subcommand
./embedded_linux_audit transfer ws://server:8080 --retry-attempts 10
```

The number of retry attempts can also be configured with the
`ELA_WS_RETRY_ATTEMPTS` environment variable (integer, 0–1000).  The CLI flag
takes precedence over the environment variable.

```sh
# Set via environment
ELA_WS_RETRY_ATTEMPTS=10 ./embedded_linux_audit --remote ws://server:8080

# Set via interactive set command (takes effect for subsequent connections)
(aa-bb-cc-dd-ee-ff)> set ELA_WS_RETRY_ATTEMPTS 10
```

## TUI — session list

When no session is attached the server displays a list of connected devices:

```
ela-terminal  —  2 session(s)
────────────────────────────────────────────────────────────
  10.0.0.5 (aa-bb-cc-dd-ee-ff)  last heartbeat: Mon Mar 10 14:32:01 UTC 2026
  router1 / factory-floor (11-22-33-44-55-66)  last heartbeat: Mon Mar 10 14:32:05 UTC 2026

↑/↓ navigate   Enter attach   q quit
```

| Key | Action |
|-----|--------|
| `↑` / `k` | Move cursor up |
| `↓` / `j` | Move cursor down |
| `Enter` | Attach to highlighted session |
| `q` | Quit the server |
| `Ctrl+C` | Quit the server |

Device labels show the alias and group separated by ` / `, followed by the MAC
address in parentheses.  When only one of alias or group is set, only that
value appears before the MAC, e.g. `router1 (11-22-33-44-55-66)` or
`factory-floor (aa-bb-cc-dd-ee-ff)`.  The group is automatically initialised
to the connecting device's source IP address on first connection.

## TUI — active session

After attaching, the operator sees a prompt and can type commands that are
sent to the agent's interactive loop:

```
Attached to router1 / factory-floor (11-22-33-44-55-66)  (type '/detach' + Enter to return)
────────────────────────────────────────────────────────────
router1 / factory-floor (11-22-33-44-55-66)> linux dmesg
...
router1 / factory-floor (11-22-33-44-55-66)>
```

The prompt is `alias (mac)>` when an alias is set, or `(mac)>` otherwise.

### Session commands

Commands prefixed with `/` are handled locally by the terminal server and are
not forwarded to the agent.  Any line that does not start with `/` is sent
verbatim to the agent's interactive loop (e.g. `linux dmesg`,
`uboot env --size 0x20000`, `set ELA_OUTPUT_FORMAT json`).

| Command | Description |
|---------|-------------|
| `/help` | Show available session commands |
| `/name [alias]` | Set or clear the alias for the current device |
| `/group [group]` | Set or clear the group for the current device |
| `/delete <group> <name>` | Delete an alias identified by its group and name |
| `/detach` | Return to the session list without closing the agent connection |

### Naming a device

```
(aa-bb-cc-dd-ee-ff)> /name production-router
[alias set to "production-router"]
production-router / 10.0.0.1 (aa-bb-cc-dd-ee-ff)>
```

Aliases are persisted to PostgreSQL and reloaded automatically on server
startup, so they survive server restarts.  Existing
`api/terminal/ela-aliases.json` entries are imported on startup for migration
compatibility.  To clear an alias, run `/name` with no argument:

```
production-router / factory-floor (aa-bb-cc-dd-ee-ff)> /name
[alias cleared]
factory-floor (aa-bb-cc-dd-ee-ff)>
```

Alias uniqueness is scoped to the group — the same alias may be used in
different groups, but two devices in the same group cannot share an alias.

### Grouping devices

Every session is automatically assigned a group on first connection, using the
source IP address of the connecting agent as the initial value:

```
(aa-bb-cc-dd-ee-ff)> /group factory-floor
[group set to "factory-floor"]
production-router / factory-floor (aa-bb-cc-dd-ee-ff)>
```

Groups are persisted to PostgreSQL alongside aliases.  To clear a group, run
`/group` with no argument:

```
production-router / factory-floor (aa-bb-cc-dd-ee-ff)> /group
[group cleared]
production-router (aa-bb-cc-dd-ee-ff)>
```

### Deleting an alias

To remove an alias without being attached to the affected session, use
`/delete` with the group and name as arguments:

```
(aa-bb-cc-dd-ee-ff)> /delete factory-floor production-router
[alias "production-router" in group "factory-floor" deleted]
```

If no alias matching the group and name combination exists, the command reports
it was not found:

```
(aa-bb-cc-dd-ee-ff)> /delete factory-floor unknown-device
[not found: "unknown-device" in group "factory-floor"]
```

### Detaching

Type `/detach` and press Enter to return to the session list.  The agent
connection stays open; output generated while detached is buffered (up to 500
lines) and flushed when the session is re-attached.

## Heartbeat

The server sends a `{"_type":"heartbeat"}` WebSocket frame every 30 seconds.
The agent responds with `{"_type":"heartbeat_ack","date":"<timestamp>"}`.  The
last acknowledged heartbeat time is shown in the session list.  If no
heartbeat arrives the session entry remains visible until the WebSocket closes.

## HTTP API

In addition to the WebSocket interface, the server exposes a small JSON HTTP API
on the same port for programmatic control of connected sessions.  When the
server is started with `--validate-key`, every endpoint except
`/terminal/healthcheck` requires the same `Authorization: Bearer <token>`
header as the WebSocket upgrade.  The `/terminal/healthcheck` endpoint is
always unauthenticated.

**Device-association scoping.** When a request's token resolves to a user, the
HTTP API exposes only the devices that user is **associated** with — the same
`user_devices` links the server records when a device phones in with that user's
agent token (see [server-side auth](../auth.md#token-scopes--agent-vs-client)).
`GET /terminal/sessions` lists only the user's own devices, and the per-device
routes (`exec`/`spawn`) treat any device the user is not associated with exactly
like one that is not connected — `404 {"error":"no active session for mac"}` —
so the API never exposes or lets you enumerate other users' devices. With no
keys configured (open mode) there is no user to scope by and every live session
is listed, matching the rest of the auth posture.

| Method & path | Purpose |
|---------------|---------|
| `GET /terminal/healthcheck` | Liveness check (always public) |
| `GET /terminal/sessions` | List connected sessions |
| `POST /terminal/<mac>/exec` | Run one command and wait for it to finish |
| `POST /terminal/<mac>/spawn` | Launch a long-running background process |
| `GET /terminal/<mac>/spawn` | List the processes spawned on a session |
| `DELETE /terminal/<mac>/spawn/<pid>` | Kill a spawned process |

### `GET /terminal/healthcheck`

Returns `200 ok` (plain text) while the server is running.

### `GET /terminal/sessions`

Lists the currently connected sessions.

```sh
curl -H "Authorization: Bearer mysecrettoken" \
    http://server:8080/terminal/sessions
```

```json
[
  {
    "mac": "aa:bb:cc:dd:ee:ff",
    "alias": "router1",
    "group": "factory-floor",
    "remoteAddress": "10.0.0.5",
    "connectedAt": "2026-06-29T14:32:01.000Z",
    "lastHeartbeat": "2026-06-29T14:32:31.000Z"
  }
]
```

Any field that is not yet known is `null` (for example `lastHeartbeat` before the
first heartbeat acknowledgement).

### `POST /terminal/<mac>/exec`

Runs a single command on the agent identified by `<mac>` and waits for it to
complete.  The command is executed via the agent's `linux execute-command`
primitive; completion is detected when the agent re-emits its prompt.

Request body:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | yes | The shell command to run on the device |
| `timeoutMs` | number | no | Max time to wait for completion (default 15000) |

```sh
curl -X POST \
    -H "Authorization: Bearer mysecrettoken" \
    -H "Content-Type: application/json" \
    -d '{"command":"uname -a","timeoutMs":10000}' \
    http://server:8080/terminal/aa:bb:cc:dd:ee:ff/exec
```

Responses:

| Status | Body | Meaning |
|--------|------|---------|
| `200` | `{ "ok": true, "output": "...", "durationMs": 123 }` | Command completed |
| `400` | `{ "error": "..." }` | Invalid MAC, missing `command`, or bad `timeoutMs` |
| `401` | `{ "error": "Unauthorized" }` | Missing/invalid bearer token (when enforced) |
| `404` | `{ "error": "no active session for mac" }` | No connected session for `<mac>` |
| `504` | `{ "ok": false, "error": "exec timed out", "output": "...", "durationMs": 15000 }` | Command did not complete before `timeoutMs`; `output` holds whatever was captured so far |

### `POST /terminal/<mac>/spawn`

Launches a **long-running** background process on the agent — for example a
`gdbserver` instance or an SSH tunnel — and returns immediately with its PID.
Unlike `exec`, the process is backgrounded on the device, so it keeps running
after the request completes and is tracked until it is killed (see `DELETE`
below) or the session disconnects.

Request body:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | yes | The program to launch on the device |
| `args` | string[] | no | Arguments passed to the program (each is shell-quoted) |
| `port` | number | no | The TCP port the process binds (1–65535). When supplied it is returned verbatim; otherwise the server watches the process output briefly for a `port <N>` line (e.g. gdbserver's `Listening on port 1234`) |

```sh
curl -X POST \
    -H "Authorization: Bearer mysecrettoken" \
    -H "Content-Type: application/json" \
    -d '{"command":"gdbserver","args":[":0","/bin/ls"]}' \
    http://server:8080/terminal/aa:bb:cc:dd:ee:ff/spawn
```

Responses:

| Status | Body | Meaning |
|--------|------|---------|
| `201` | `{ "pid": 4242, "port": 34567 }` | Process started; `port` is omitted when neither supplied nor detected |
| `400` | `{ "error": "..." }` | Invalid MAC, missing `command`, non-string `args`, or out-of-range `port` |
| `401` | `{ "error": "Unauthorized" }` | Missing/invalid bearer token (when enforced) |
| `404` | `{ "error": "no active session for mac" }` | No connected session for `<mac>` |
| `504` | `{ "error": "spawn timed out" }` | The agent did not report a PID in time |

### `GET /terminal/<mac>/spawn`

Lists the processes currently tracked for the session.

```json
[
  {
    "pid": 4242,
    "command": "gdbserver",
    "args": [":0", "/bin/ls"],
    "port": 34567,
    "startedAt": "2026-06-29T14:35:10.000Z"
  }
]
```

`port` is omitted for spawns whose bound port was never supplied or detected.

### `DELETE /terminal/<mac>/spawn/<pid>`

Kills a tracked spawn (via `kill <pid>` on the device) and removes it from the
registry.  Only PIDs returned by a previous `spawn` call are accepted.

```sh
curl -X DELETE \
    -H "Authorization: Bearer mysecrettoken" \
    http://server:8080/terminal/aa:bb:cc:dd:ee:ff/spawn/4242
```

Responses:

| Status | Body | Meaning |
|--------|------|---------|
| `200` | `{ "ok": true }` | Process killed and untracked |
| `400` | `{ "error": "invalid pid" }` | `<pid>` is not a positive integer |
| `401` | `{ "error": "Unauthorized" }` | Missing/invalid bearer token (when enforced) |
| `404` | `{ "error": "no such spawn" }` | No tracked spawn with that PID |
| `404` | `{ "error": "no active session for mac" }` | No connected session for `<mac>` |

## nginx reverse proxy

To expose the terminal server over HTTPS alongside the agent helper API, use
the example config in `nginx/ela.conf`.  The key points for the terminal
endpoint:

```nginx
location /api/terminal/ {
    proxy_pass http://127.0.0.1:8080/;

    proxy_set_header Upgrade    $http_upgrade;
    proxy_set_header Connection "upgrade";

    # Must be longer than the 30s heartbeat interval
    proxy_read_timeout 120s;
    proxy_send_timeout 120s;
}
```

The agent then connects to:

```sh
./embedded_linux_audit transfer --remote wss://ela.example.com/api/terminal
```

nginx strips `/api/terminal/` and forwards to `ws://127.0.0.1:8080/terminal/<mac>`.

See [nginx configuration](../nginx.md) for the full config and TLS setup.
