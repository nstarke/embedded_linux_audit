# API Helper Server

Use the Node.js helper in `api/agent/` as the local helper for testing HTTP/HTTPS POST output and serving downloaded release binaries/test scripts.

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
- `--https` enables HTTPS with a self-signed localhost certificate.
- `--clean` deletes runtime upload data under the configured data directory before startup, but preserves cached release binaries in `<data-dir>/release_binaries`.
- `--force-download` refreshes the cached release binaries in `<data-dir>/release_binaries`.

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
- runtime upload data may also be stored under `<data-dir>/<startup_timestamp>/<mac_address>/...` for `fs`, `file-list`, `env`, `logs`, `dmesg`, `orom`, `uboot/image`, and `uboot/env`.
- `/upload/log` and `/upload/logs` are both accepted and stored under `<data-dir>/<startup_timestamp>/<mac_address>/logs/`.
- downloaded release binaries are cached separately under `<data-dir>/release_binaries` by default.
- `GET /` returns an HTML index of release binaries and agent test scripts.
- `GET /tests/agent/:name` serves `.sh` files from `tests/agent/shell/` (for example `/tests/agent/download_tests.sh`, backed by `tests/agent/shell/download_tests.sh`). `GET /isa/:isa` and `GET /uboot-env/:env_filename` serve ISA binaries and U-Boot environment helper files respectively.
- set `ELA_AGENT_SKIP_ASSET_SYNC=true` or pass `--skip-asset-sync` to skip GitHub release refresh during startup, which is useful for container deployments.
