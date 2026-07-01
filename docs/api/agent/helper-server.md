# API Helper Server

Use the Node.js helper in `api/agent/` as the local helper for testing HTTP/HTTPS POST output and serving per-user agent binaries/test scripts.

## Per-user agent launchers (generic build + self-extracting wrapper)

Agent binaries are no longer downloaded from GitHub, and they are **no longer
cross-compiled per user**. The agent is compiled **once** into generic
(unembedded) binaries — one per ISA — at `<data-dir>/release_binaries/generic/ela-<isa>`.
The `builder` worker produces these automatically on first start (a one-time
job), so there is no per-user compile and nothing to wait on when creating a
user.

When a token is created (`tools/add-user-key.js`), each generic binary is
wrapped in a small **self-extracting POSIX-sh launcher** that, at runtime, sets
`ELA_API_KEY=<token>` and (on a bare run) seeds `/tmp/.ela.conf` with the
terminal-API URL so the agent phones home — then extracts and execs the embedded
binary, forwarding all arguments. This is pure file I/O and completes instantly.
The launchers are written flat to
`<data-dir>/release_binaries/users/<keyHash>/ela-<isa>` where `<keyHash>` is the
SHA-256 of the token.

`GET /isa/:token/:isa` is **unauthenticated** and serves the launcher for the
token given in the URL path (the server hashes it to `users/<sha256(token)>/`).
Save it, `chmod +x`, and run it: `./ela-<isa>` phones home on a bare run, while
`./ela-<isa> linux dmesg` runs a command locally (the same duality an
embedded-URL binary had). The token is present in the launcher file in
cleartext, so treat the downloaded file as a credential. See
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
- `--clean` deletes runtime upload data under the configured data directory before startup, but preserves the generic binaries and per-user launchers in `<data-dir>/release_binaries`.

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
- the one-time generic binaries live under `<data-dir>/release_binaries/generic/ela-<isa>`; per-user launchers live under `<data-dir>/release_binaries/users/<keyHash>/` by default.
- `GET /` returns an HTML index of the authenticated user's release binaries and agent test scripts.
- `GET /tests/agent/:name` serves `.sh` files from `tests/agent/shell/` (for example `/tests/agent/download_tests.sh`, backed by `tests/agent/shell/download_tests.sh`). `GET /isa/:token/:isa` (unauthenticated) and `GET /uboot-env/:env_filename` serve ISA binaries and U-Boot environment helper files respectively. `GET /isa/:token/:isa` selects the per-user directory by hashing the token in the URL path.

PCAP WebSocket handling:

- `ws://<host>/pcap/<mac>` and `wss://<host>/pcap/<mac>` accept binary pcap frames from `embedded_linux_audit linux pcap`.
- the `<mac>` path segment must be a valid MAC address and bearer authentication is enforced when API keys are configured.
- each connection writes one `.pcap` artifact under `<data-dir>/<startup_timestamp>/<mac_address>/pcap/`.
- after the WebSocket closes, the API persists an `uploads` row with upload type `pcap` and `localArtifactPath` pointing at the saved `.pcap` file.
