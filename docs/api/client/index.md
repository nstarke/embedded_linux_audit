# Client API

The client API (`api/client/`) exposes the artifacts uploaded by the agent as
JSON, so an operator's own tooling can read back what was collected. It is a
read-only service, separate from the ingest-side agent helper API.

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

## Per-user isolation

Each upload records the `user_id` of the agent token that produced it (the agent
API stamps `req.authUser` onto the row). The client API resolves the client
token to its user and returns **only that user's artifacts**. Uploads with no
owner (legacy ingests, or ingests made without an authenticated agent token) are
not visible to any client token.

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
```
