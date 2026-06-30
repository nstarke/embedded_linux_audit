# API Helper Server

Use the Node.js helper in `api/agent/` as the local helper for testing HTTP/HTTPS POST output and serving per-user agent binaries/test scripts.

## Per-user, token-embedded agent binaries

Agent binaries are no longer downloaded from GitHub. Instead they are
cross-compiled in the helper container with each user's API token baked in, at
the moment that token is created (`tools/add-user-key.js`). The binaries are
written flat to `<data-dir>/release_binaries/users/<keyHash>/ela-<isa>` where
`<keyHash>` is the SHA-256 of the token.

`GET /isa/:isa` serves the set matching the bearer token presented on the
request: the server resolves the token to its hash and reads from that user's
directory. Requests without a token fall back to the shared
`<data-dir>/release_binaries` pool (empty by default). See
[token creation and docker operations](../docker-operations.md) and
[server-side auth](../auth.md).

Example:

```bash
cd api/agent && npm start -- --host 0.0.0.0 --port 5000 --log-prefix post_requests
```

You can also enable verbose per-request console logging with either:

```bash
cd api/agent && npm start --verbose
```

or:

```bash
cd api/agent && npm start -- --verbose
```

Additional server options:

- `--data-dir` changes the base directory used for helper-server data storage. By default this is `api/agent/data`.
- `--reuse-last-data-dir` reuses the latest existing timestamped runtime data directory under `--data-dir`; if none exists, startup creates and uses the current timestamp directory.
- `--https` enables HTTPS with a self-signed localhost certificate.
- `--clean` deletes runtime upload data under the configured data directory before startup, but preserves the per-user release binaries in `<data-dir>/release_binaries`.

POST handling notes:

- accepted `Content-Type` values:
  - `text/plain`
  - `text/csv`
  - `application/x-ndjson`
  - `application/octet-stream`
- invalid or missing `Content-Type` values are rejected with HTTP `415`.
- log output is split by content type into files derived from `--log-prefix` (for example `post_requests.text_plain.log`, `post_requests.text_csv.log`, and `post_requests.application_octet_stream.log`).
- `application/octet-stream` uploads are additionally written as raw `.bin` files under the per-host runtime upload directories for later analysis.
- upload metadata and normalized records are persisted in PostgreSQL.
- runtime upload data may also be stored under `<data-dir>/<startup_timestamp>/<mac_address>/...` for `fs`, `file-list`, `env`, `logs`, `dmesg`, `coredump`, `orom`, `pcap`, `uboot/image`, and `uboot/env`.
- `/upload/log` and `/upload/logs` are both accepted and stored under `<data-dir>/<startup_timestamp>/<mac_address>/logs/`.
- per-user release binaries live under `<data-dir>/release_binaries/users/<keyHash>/` by default.
- `GET /` returns an HTML index of the authenticated user's release binaries and agent test scripts.
- `GET /tests/agent/:name` serves `.sh` files from `tests/agent/shell/` (for example `/tests/agent/download_tests.sh`, backed by `tests/agent/shell/download_tests.sh`). `GET /isa/:isa` and `GET /uboot-env/:env_filename` serve ISA binaries and U-Boot environment helper files respectively. `GET /isa/:isa` selects the per-user directory from the presented bearer token.

PCAP WebSocket handling:

- `ws://<host>/pcap/<mac>` and `wss://<host>/pcap/<mac>` accept binary pcap frames from `embedded_linux_audit linux pcap`.
- the `<mac>` path segment must be a valid MAC address and bearer authentication is enforced when API keys are configured.
- each connection writes one `.pcap` artifact under `<data-dir>/<startup_timestamp>/<mac_address>/pcap/`.
- after the WebSocket closes, the API persists an `uploads` row with upload type `pcap` and `localArtifactPath` pointing at the saved `.pcap` file.
