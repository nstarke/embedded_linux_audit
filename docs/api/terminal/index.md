# WebSocket Terminal Server (`api/terminal`)

The terminal server provides a browser-less, operator-facing interface for
managing multiple simultaneous agent connections.  Each agent that connects
via `transfer --remote ws://...` appears as a session.  The operator interacts
with the running sessions through a terminal TUI served on the machine running
the server.

## Requirements

- Node.js ≥ 18
- `ws` npm package (`npm install` inside `api/terminal/`)

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
./embedded_linux_audit transfer --remote ws://ela.example.com/terminal

# Secure WebSocket — via nginx on port 443
./embedded_linux_audit transfer --remote wss://ela.example.com/terminal

# Skip TLS certificate verification (self-signed certs, testing only)
./embedded_linux_audit --insecure transfer --remote wss://ela.example.com/terminal
```

The agent appends its MAC address to the URL path
(`/terminal/<mac>`), which the server uses as the session identifier.  If a
session already exists for that MAC the previous connection is closed and
replaced.

## TUI — session list

When no session is attached the server displays a list of connected devices:

```
ela-terminal  —  2 session(s)
────────────────────────────────────────────────────────────
  aa-bb-cc-dd-ee-ff  last heartbeat: Mon Mar 10 14:32:01 UTC 2026
  router1 (11-22-33-44-55-66)  last heartbeat: Mon Mar 10 14:32:05 UTC 2026

↑/↓ navigate   Enter attach   q quit
```

| Key | Action |
|-----|--------|
| `↑` / `k` | Move cursor up |
| `↓` / `j` | Move cursor down |
| `Enter` | Attach to highlighted session |
| `q` | Quit the server |
| `Ctrl+C` | Quit the server |

Device labels show the alias if one has been set, followed by the MAC address
in parentheses, e.g. `router1 (11-22-33-44-55-66)`.

## TUI — active session

After attaching, the operator sees a prompt and can type commands that are
sent to the agent's interactive loop:

```
Attached to router1 (11-22-33-44-55-66)  (type '/detach' + Enter to return)
────────────────────────────────────────────────────────────
router1 (11-22-33-44-55-66)> linux dmesg
...
router1 (11-22-33-44-55-66)>
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
| `/name <alias>` | Assign a human-readable alias to the device |
| `/detach` | Return to the session list without closing the agent connection |

### Naming a device

```
(aa-bb-cc-dd-ee-ff)> /name production-router
[device named: production-router]
production-router (aa-bb-cc-dd-ee-ff)>
```

The alias persists for the lifetime of the server process.  It is shown in
both the session list and the active-session prompt.

### Detaching

Type `/detach` and press Enter to return to the session list.  The agent
connection stays open; output generated while detached is buffered (up to 500
lines) and flushed when the session is re-attached.

## Heartbeat

The server sends a `{"_type":"heartbeat"}` WebSocket frame every 30 seconds.
The agent responds with `{"_type":"heartbeat_ack","date":"<timestamp>"}`.  The
last acknowledged heartbeat time is shown in the session list.  If no
heartbeat arrives the session entry remains visible until the WebSocket closes.

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
