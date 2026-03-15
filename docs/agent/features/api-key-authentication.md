# API Key Authentication

The agent supports bearer token authentication when uploading data to the
agent helper API or connecting to the WebSocket terminal server.  The token
is sent as an `Authorization: Bearer <token>` HTTP header on every request.
No token is required by default; one is only needed if the receiving server
was started with `--validate-key`.

## Providing a token

Three sources are accepted, tried in the order listed below.  The first
source that the server accepts is locked in for all subsequent requests in
the same run.

### 1. `--api-key` command-line argument

```sh
./embedded_linux_audit --api-key mysecrettoken --output-http http://server/upload linux dmesg
```

The `=` form is also accepted:

```sh
./embedded_linux_audit --api-key=mysecrettoken ...
```

The token must be at most 1024 characters.

### 2. `ELA_API_KEY` environment variable

```sh
ELA_API_KEY=mysecrettoken ./embedded_linux_audit --output-http http://server/upload linux dmesg
```

### 3. `/tmp/ela.key` file

If neither the CLI argument nor the environment variable is set, the agent
reads `/tmp/ela.key`.  The file may contain multiple tokens, one per line;
all non-empty lines are tried in order.

```sh
echo mysecrettoken > /tmp/ela.key
chmod 600 /tmp/ela.key
./embedded_linux_audit --output-http http://server/upload linux dmesg
```

## Multi-source fallback

All three sources are collected at startup and de-duplicated while preserving
order.  On a `401 Unauthorized` response the agent automatically retries the
request with the next candidate token.  Once a token is accepted the agent
confirms it and uses it for all subsequent requests in the same run without
further retries.

This means you can set `ELA_API_KEY` to a primary token and list fallback
tokens in `/tmp/ela.key`; the agent will find a working one without user
intervention.

## 401 warning

If no token is set and the server returns `401 Unauthorized`, or if all
candidate tokens are exhausted without success, the agent prints a warning to
stderr:

```
warning: server returned 401 Unauthorized
  Set a bearer token via --api-key, ELA_API_KEY, or /tmp/ela.key
```

The agent continues running after the warning; output that could not be
uploaded is not retried.

## Setting the key at runtime (interactive mode)

Inside an interactive session the `set` command can update `ELA_API_KEY` for
commands run later in the same session:

```
ela> set ELA_API_KEY mysecrettoken
ELA_API_KEY=<set>
```

The value is never printed back.  Note that the key list built at startup is
not re-initialised by `set`; the environment variable update takes effect for
any subprocess the agent spawns but does not change which token is sent on
HTTP/WebSocket connections already in progress.

## WebSocket sessions (`--remote`)

The same token sources apply when `transfer --remote ws://host:port` or
`transfer --remote wss://host:port` is used.  The token is sent in the
`Authorization` header of the WebSocket upgrade request.  If the server
returns `401` the agent prints:

```
ws: server returned 401 Unauthorized
  Set a bearer token via --api-key, ELA_API_KEY, or /tmp/ela.key
```

## Examples

```sh
# CLI argument
./embedded_linux_audit \
    --api-key mysecrettoken \
    --output-http https://ela.example.com/api/agent/upload \
    linux dmesg

# Environment variable
ELA_API_KEY=mysecrettoken ./embedded_linux_audit \
    --output-http https://ela.example.com/api/agent/upload \
    uboot env --size 0x20000

# Key file (multiple tokens)
printf 'token1\ntoken2\n' > /tmp/ela.key
chmod 600 /tmp/ela.key
./embedded_linux_audit \
    --output-http https://ela.example.com/api/agent/upload \
    linux dmesg

# WebSocket remote session
./embedded_linux_audit \
    --api-key mysecrettoken \
    transfer --remote wss://ela.example.com/api/terminal
```
