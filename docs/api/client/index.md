# Client API

The client API (`api/client/`) exposes the artifacts uploaded by the agent as
JSON, so an operator's own tooling can read back what was collected, and provides
**live terminal control** of connected devices (sessions/exec/spawn) by relaying
commands to the agent-only terminal server over an internal queue. It is the
single operator-facing API, separate from the ingest-side agent helper API.

## Interactive docs (Swagger UI)

The service ships a built-in OpenAPI 3 description and a Swagger UI web client
for trying the API from a browser — both are public (no token needed to view):

- `GET /docs` — Swagger UI. Click **Authorize**, paste your **client** token,
  then use **Try it out** on any route.
- `GET /openapi.json` — the raw OpenAPI 3 document (import into Postman, codegen,
  etc.).

Direct (the client-api port): <http://localhost:7000/docs/>. Through the bundled
nginx proxy: `https://<host>/client/docs/` (keep the trailing slash). The OpenAPI
`servers` base is set automatically — nginx sends `X-Forwarded-Prefix: /client`,
so the spec served behind the proxy uses `/client` and **Try it out** targets
`/client/uploads…`; reached directly it uses `/`. No dropdown selection needed.

The OpenAPI document's upload-type enum is generated from
`api/lib/uploadTypes.js`, so it always matches what the service accepts.

## Authentication — the client token

The client API uses a **client-scoped** bearer token that is distinct from the
agent token. Both tokens are created for a user by `tools/add-user-key.js`:

```sh
node tools/add-user-key.js --username alice
# or inside the container:
docker compose exec agent-api node /app/tools/add-user-key.js --username alice
```

This prints two keys, each shown once:

```
agent key:  <token embedded into alice's agent binaries>
client key: <token for the client API>
```

Only the SHA-256 hashes are stored (`api_keys.key_hash`); the rows are
distinguished by `api_keys.scope` (`'agent'` vs `'client'`). The agent helper,
terminal, and gdb services accept `'agent'` keys; the client API accepts
`'client'` keys. Presenting an agent token to the client API (or vice-versa) is
rejected.

Send the token on every request:

```
Authorization: Bearer <client-key>
```

## Visibility by device association

The client API returns artifacts from the **devices you've associated** — not
just the ones your token uploaded. A user is associated with a device when that
user's agent (authenticating with its agent token) connects to the
[terminal API](../terminal/index.md) for the device's MAC; binaries built with
an embedded server URL do this automatically on first run. The association is
recorded in `user_devices`.

So a client token sees an artifact iff its user is associated with that
artifact's device. A device can be associated with **multiple** users (each user
whose agent has registered it via the terminal API) — all of them see its
artifacts. A user who has not associated any devices sees nothing.

## Routes

All routes are mounted at the service root (behind nginx they are reached under
`/client/`, e.g. `GET /client/uploads`). The deployed default port is `7000`
(`ELA_CLIENT_PORT`).

| Method & path | Description |
| --- | --- |
| `GET /uploads` | List the upload types the user has, with counts: `{ "uploadTypes": [{ "uploadType": "dmesg", "count": 3 }] }`. |
| `GET /uploads/:type` | List artifact metadata for `:type` (newest first). Supports `?limit` (max 1000, default 100) and `?offset`. Returns `{ uploadType, limit, offset, uploads: [...] }`. Payload bodies are excluded. |
| `GET /uploads/:type/:id` | A single artifact record including parsed `payloadText` / `payloadJson`. `404` if it does not exist or is not owned by the user. |
| `GET /uploads/:type/:id/raw` | The original artifact bytes: `application/octet-stream` payloads are returned as raw bytes; text/JSON payloads are returned with their stored content type. |

`:type` must be one of the known upload types (`api/lib/uploadTypes.js`); unknown
types return `404`. `:id` must be numeric.

### Terminal control

Live control of connected devices also lives on the client API. These commands
are **not** executed here: the client API enqueues them on the internal
`ela-terminal-commands` Redis queue, the terminal server runs them against the
live agent WebSocket session and queues the result back, and the client API
relays it to you. The terminal server exposes no operator HTTP surface.

| Method & path | Description |
| --- | --- |
| `GET /terminal/sessions` | List connected devices you are associated with: `{ "sessions": [{ mac, alias, group, remoteAddress, connectedAt, lastHeartbeat }] }`. |
| `POST /terminal/:mac/exec` | Run one command and wait for its output. Body `{ "command": "uname -a", "timeoutMs"?: <=60000 }` → `{ ok, output, durationMs }`. |
| `POST /terminal/:mac/spawn` | Launch a long-running process. Body `{ "command", "args"?: [...], "port"?: 1-65535 }` → `201 { pid, port? }`. |
| `GET /terminal/:mac/spawn` | List tracked spawns for the device: `{ "spawns": [...] }`. |
| `DELETE /terminal/:mac/spawn/:pid` | Kill a tracked spawn → `{ "ok": true }`. |

**MAC ACLs.** Every terminal route is restricted to devices you are
**associated** with (the same `user_devices` links used for artifact
visibility). A device you are not associated with — or one that is not
connected — returns `404 {"error":"no active session for mac"}`, so you cannot
issue commands to, or enumerate, other users' devices. If the terminal server is
unavailable or a command does not complete in time, the route returns `504`.

### Artifact metadata fields

`id`, `uploadType`, `contentType`, `macAddress` (of the uploading device),
`srcIp`, `apiTimestamp`, `requestFilePath`, `localArtifactPath`, `isSymlink`,
`symlinkPath`, `payloadSha256`, `payloadBytes`.

## Example

```sh
KEY=<client-key>
BASE=http://localhost/client

curl -H "Authorization: Bearer $KEY" "$BASE/uploads"
curl -H "Authorization: Bearer $KEY" "$BASE/uploads/dmesg?limit=20"
curl -H "Authorization: Bearer $KEY" "$BASE/uploads/dmesg/42"
curl -H "Authorization: Bearer $KEY" "$BASE/uploads/dmesg/42/raw"

# terminal control (only for devices you are associated with)
curl -H "Authorization: Bearer $KEY" "$BASE/terminal/sessions"
curl -X POST -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    -d '{"command":"uname -a"}' "$BASE/terminal/aa:bb:cc:dd:ee:ff/exec"
```
