# API Key Authentication — Server Side

Both web API servers (`api/agent` and `api/terminal`) share the same
authentication module (`api/auth.js`).  Authentication is **opt-in**:
by default neither server enforces tokens, so existing deployments are
unaffected.

## Key file format — `ela.key`

Create `api/ela.key` (one bearer token per line, UTF-8, any line ending):

```
mysecrettoken
anothertoken
```

- Blank lines and lines containing only whitespace are ignored.
- There is no maximum number of tokens; all listed tokens are valid
  simultaneously.
- The file is read once at server startup.  Restart the server to pick up
  changes.

## Enabling enforcement — `--validate-key`

Pass `--validate-key` to either server to require a valid bearer token on
every request.  If `ela.key` is missing or contains no valid tokens the
server prints an error and exits immediately:

```
error: --validate-key is set but ela.key is missing or contains no valid tokens
```

### Agent helper API (`api/agent`)

```sh
cd api/agent
node server.js --validate-key
# or
npm run start:secure
```

### Terminal server (`api/terminal`)

```sh
cd api/terminal
node server.js --validate-key
# or
npm run start:secure
```

## How clients authenticate

Clients must include the bearer token in every request:

```
Authorization: Bearer <token>
```

The agent supplies this header automatically when `--api-key`, `ELA_API_KEY`,
or `/tmp/ela.key` is configured.  See
[API Key Authentication — agent side](../agent/features/api-key-authentication.md)
for details.

## Security properties

- **Constant-time comparison**: `crypto.timingSafeEqual` is used, padded to
  the same length, so the response time does not reveal whether the submitted
  token is closer to or further from any stored token.
- **No short-circuit**: every loaded token is compared on every request,
  regardless of whether a match has already been found.  This prevents
  timing side-channels that would otherwise expose the number of tokens or
  their order.
- **No logging of token values**: rejected requests emit an HTTP `401` with
  `{"error":"Unauthorized"}` body; the submitted token is never written to
  logs.
- WebSocket connections are rejected with HTTP `401` before the upgrade
  handshake completes, so no WebSocket connection object is created for
  unauthorised clients.

## nginx and TLS

When using the nginx reverse proxy (`nginx/ela.conf`) the `Authorization`
header is forwarded to both backends:

```nginx
proxy_set_header Authorization $http_authorization;
```

This means TLS termination is handled by nginx; the backends on localhost
receive plain HTTP/WS with the header intact.  See
[nginx configuration](nginx.md) for the full setup.

## Quick-start example

```sh
# 1. Create the key file
echo 'mysecrettoken' > api/ela.key
chmod 600 api/ela.key

# 2. Start servers with enforcement
cd api/agent   && npm run start:secure &
cd api/terminal && npm run start:secure &

# 3. Run the agent with the token
./embedded_linux_audit \
    --api-key mysecrettoken \
    --output-http http://localhost:5000/upload \
    linux dmesg

# 4. Connect a remote session
./embedded_linux_audit \
    --api-key mysecrettoken \
    transfer --remote ws://localhost:8080
```
