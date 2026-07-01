# Docker Operations Guide

This guide covers how to run, inspect, and maintain the containerized
`embedded_linux_audit` server stack.

## Services

A default `docker compose up` starts eight containers:

- `postgres` - bundled PostgreSQL database (defined in `docker-compose.override.yml`; see [External PostgreSQL](#external-postgresql))
- `redis` - queue broker for binary-build jobs (see [Build queue](#build-queue))
- `builder` - worker that cross-compiles per-user agent binaries off the queue
- `agent-api` - HTTP upload and asset-serving API
- `client-api` - read-back API for uploaded artifacts ([client API](client/index.md))
- `terminal-api` - WebSocket terminal server
- `gdb-api` - WebSocket GDB RSP bridge
- `nginx` - frontend reverse proxy for the APIs

The API services live in
[docker-compose.yml](/home/nick/Documents/git/embedded_linux_audit/docker-compose.yml);
the bundled database is an overlay so it can be swapped for an external server.

Traffic flow:

- `http://localhost/` -> `agent-api`
- `http://localhost/client/...` -> `client-api`
- `http://localhost/terminal/<mac>` -> `terminal-api`
- `http://localhost/gdb/...` -> `gdb-api`
- `http://localhost/pcap/<mac>` -> `agent-api`

## Prerequisites

- Docker Engine with Compose support
- Enough free disk space for PostgreSQL data and uploaded binary artifacts
- A free listener on TCP port `80`

On Debian/Ubuntu systems you can install the required Docker packages with:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-buildx docker-compose-v2
```

## First Startup

From the repository root:

```bash
docker compose up --build
```

If you want the bundled nginx frontend to advertise a specific hostname rather
than the default `example.com`, use the installer instead:

```bash
./nginx/install.sh ela.example.com
```

Expected behavior on first boot:

1. `postgres` initializes the `embedded_linux_audit` database.
2. `agent-api` connects to PostgreSQL and runs pending migrations automatically.
3. `terminal-api` connects to the same PostgreSQL instance and runs the same migrations automatically.
4. `nginx` starts after the APIs are reachable and exposes the stack on port `80`.

## Running In The Background

```bash
docker compose up -d --build
```

To view status:

```bash
docker compose ps
```

To view logs:

```bash
docker compose logs -f
```

To follow one service:

```bash
docker compose logs -f agent-api
docker compose logs -f terminal-api
docker compose logs -f postgres
docker compose logs -f nginx
```

## Shutdown

Stop containers but keep data volumes:

```bash
docker compose down
```

Stop containers and remove volumes too:

```bash
docker compose down -v
```

Use `-v` only when you want to destroy the database state and uploaded runtime data.

## Volumes And Persistence

The compose stack uses two named volumes:

- `postgres-data` - PostgreSQL database files
- `agent-data` - runtime artifact storage used by the agent API

These volumes survive `docker compose down` unless `-v` is used.

## Environment Overrides

The compose file defines default values for the APIs and database. You can
override them with shell environment variables or by editing the compose file.

Important database variables used by the APIs (see
[External PostgreSQL](#external-postgresql)):

- `ELA_DB_HOST`
- `ELA_DB_PORT`
- `ELA_DB_NAME`
- `ELA_DB_USER`
- `ELA_DB_PASSWORD`
- `ELA_DATABASE_URL`

Important agent API variables:

- `ELA_AGENT_HOST`
- `ELA_AGENT_PORT`
- `ELA_AGENT_DATA_DIR`
- `ELA_AGENT_ASSETS_DIR` (overrides the default `<data-dir>/release_binaries`)

> Agent binaries are no longer fetched from GitHub releases, so the former
> `ELA_AGENT_SKIP_ASSET_SYNC`, `ELA_AGENT_REPO`, and `GITHUB_TOKEN` variables and
> the `--repo`/`--github-token`/`--force-download`/`--skip-asset-sync` flags have
> been removed. See [Creating users and per-user binaries](#creating-users-and-per-user-binaries).

The bundled agent container starts with `--reuse-last-data-dir`, so container
restarts continue writing runtime artifacts into the latest timestamped
directory already present in the `agent-data` volume instead of creating a new
timestamp on every boot.

Build-queue variables (used by `agent-api` to enqueue and `builder` to consume):

- `ELA_REDIS_HOST` / `REDIS_HOST` (default `redis`)
- `ELA_REDIS_PORT` / `REDIS_PORT` (default `6379`)
- `ELA_REDIS_DATA_DIR` (host path for the redis volume, default `/data/redis`)
- `ELA_BUILD_SRC_DIR` (host repo mounted into `builder` at `/src`, default `.`)
- `ELA_BUILD_CONCURRENCY` — number of builds the `builder` runs at once
  (default `1`; keep at 1 unless builds no longer share `generated/`/`third_party`)
- `ELA_BUILD_LOCK_DURATION_MS` — how long a build may hold its BullMQ job lock
  before the job is considered stalled (default `1800000` = 30 min). Raise this
  if long builds fail with `job stalled more than allowable limit`; the worker
  renews the lock every `lockDuration / 2` while a build runs.
- `ELA_BUILD_STALLED_INTERVAL_MS` — how often the worker scans for stalled jobs
  (default `30000`)
- `ELA_BUILD_MAX_STALLED_COUNT` — times a stalled job is recovered before being
  failed (default `3`)
- `ELA_SERVER_URL` — base terminal-API WS URL (e.g. `wss://ela.example.com`)
  baked into each user's launcher so a bare run auto-connects to the terminal
  API. Empty by default (no phone-home); `nginx/install.sh` defaults it to
  `wss://<hostname>` and **persists it to the env file Compose reads** (the
  `--env-file`, else `<repo>/.env`), so `add-user-key` run later still bakes it
  in. See [Server URL / phone-home](#server-url--phone-home).

Important terminal API variables:

- `ELA_TERMINAL_HOST`
- `ELA_TERMINAL_PORT`
- `ELA_KEY_PATH`

Example override at launch time:

```bash
ELA_DB_PASSWORD=strongpassword docker compose up -d --build
```

## External PostgreSQL

By default the stack runs a bundled `postgres` container. The bundled database
is defined in `docker-compose.override.yml`, which Compose automatically merges
into `docker-compose.yml` for plain `docker compose` commands — so
`docker compose up` runs the full stack with a local database, unchanged.

To point the APIs at an **existing** PostgreSQL server and **not** run a second
database container, start Compose with the base file only and set the
connection variables:

```bash
ELA_DB_HOST=db.example.com \
ELA_DB_USER=ela \
ELA_DB_PASSWORD=secret \
ELA_DB_NAME=embedded_linux_audit \
docker compose -f docker-compose.yml up -d
```

Using `-f docker-compose.yml` excludes the override file, so the `postgres`
service is not defined or started. The database must be reachable from the
containers and already exist; the APIs create their tables via migrations on
startup. `ELA_DATABASE_URL` may be used instead of the discrete fields.

The installer wraps this:

```bash
# bundled database (default)
./nginx/install.sh ela.example.com

# external database
./nginx/install.sh ela.example.com \
    --db-host db.example.com --db-user ela --db-password secret
```

`--db-host` switches the installer to external mode: it omits the bundled
`postgres` container, skips creating the PostgreSQL data directory, and starts
only the API services. `--db-port`, `--db-name`, `--db-user`, and
`--db-password` customize the connection (and the bundled container's
credentials when no `--db-host` is given).

## Migrations

The APIs run migrations on startup automatically. The migration runner lives in:

- [api/lib/db/migrate.js](/home/nick/Documents/git/embedded_linux_audit/api/lib/db/migrate.js)

If you need to run migrations manually inside the `agent-api` container:

```bash
docker compose run --rm agent-api node /app/api/lib/db/migrate.js
```

## Creating users and per-user launchers

The agent is cross-compiled **once** into generic (unembedded) binaries — one
per ISA — that carry no token or URL. Each user then downloads a small
**self-extracting launcher** that wraps a generic binary and sets their token
and the terminal-API URL at runtime. There is **no per-user compile**, so
creating a user is instant.

The one-time generic build runs in the `builder` container (off the same Redis
queue), which compiles from the host repo mounted at `/src`, so submodules must
be initialized on the host first:

```bash
git submodule update --init --recursive
docker compose up -d   # starts postgres, redis, builder, the APIs, nginx
```

On first start the `builder` notices `<data-dir>/release_binaries/generic/` is
empty and enqueues the one-time generic build automatically. Watch it finish:

```bash
docker compose logs -f builder
docker compose exec agent-api node /app/tools/build-status.js   # counts + recent jobs
```

Then create a user (this needs the generic binaries to exist):

```bash
docker compose exec agent-api node /app/tools/add-user-key.js --username alice
```

This creates two scoped tokens, prints each once, assembles the launchers, and
returns immediately:

```
agent key:  <set at runtime by alice's launcher via ELA_API_KEY>
client key: <for the client API>

Launchers written (15 ISAs) -> /data/agent/release_binaries/users/<sha256(agent-key)>
```

Only the SHA-256 hashes are stored. The launchers are at
`<data-dir>/release_binaries/users/<sha256(agent-key)>/ela-<isa>` on the shared
`agent-data` volume. Pass `--skip-build` to only create the database records,
`--key <token>` to supply a specific agent token, or `--insecure` to have the
launcher skip TLS verification when phoning home. If the generic binaries do not
exist yet, `add-user-key` prints a hint to wait for the builder and re-run.

### Server URL / phone-home

If `ELA_SERVER_URL` is set (a base WS URL such as `wss://ela.example.com`) — or
`add-user-key --server-url <wss://host>` is passed — the URL is baked into the
launcher. Run with **no arguments** the launcher invokes the agent with
`--remote <url>` (plus `--insecure` if `add-user-key --insecure` was used), so it
connects to the terminal API at `<url>/terminal/<mac>`, authenticates with the
user's token, and daemonizes — the device shows up in the terminal API on its
own. Run with arguments (`./ela-<isa> linux dmesg`) it runs that command locally
instead. **With no server URL configured the launcher just sets the token and a
bare run prints the agent help** — set `ELA_SERVER_URL` (or `--server-url`) and
re-run `add-user-key` to enable phone-home.

The download endpoint is **unauthenticated** — the token rides in the URL path —
so a freshly provisioned host with no agent yet can pull its launcher with a
plain GET, then run it:

```bash
curl http://localhost/isa/<agent-key>/x86_64 -o ela-x86_64
chmod +x ela-x86_64 && ./ela-x86_64        # bare run -> phones home
```

`GET /isa/:token/:isa` hashes the path token (`sha256`) to locate that user's
launcher set and serves the matching architecture; an unknown token yields
`404`. The agent token appears in the URL (and in any access logs/proxies) **and**
inside the launcher file itself, so treat both as credentials.

### Removing a user

`tools/remove-user-key.js` is the inverse of `add-user-key.js`:

```bash
docker compose exec agent-api node /app/tools/remove-user-key.js --username alice
```

It deletes the user row (its `api_keys` cascade-delete) and the per-user launcher
directories `users/<keyHash>/`. Uploaded artifacts are **retained** but unlinked
from the user (`uploads.user_id` → NULL), so they no longer appear in the client
API. Flags: `--keep-binaries`, `--keep-queue`, `--assets-dir <dir>`. (Per-user
builds no longer exist, so there is normally nothing in the queue to remove.)

### Reading back artifacts (client API)

Use the **client key** with the [client API](client/index.md) to read back what
the agent uploaded for that user:

```bash
curl -H "Authorization: Bearer <client-key>" http://localhost/client/uploads
curl -H "Authorization: Bearer <client-key>" http://localhost/client/uploads/dmesg
```

The client API only returns artifacts uploaded by the same user's agent.

If a migration fails:

1. Inspect logs with `docker compose logs agent-api`.
2. Confirm PostgreSQL is healthy with `docker compose ps`.
3. Fix the underlying issue.
4. Re-run the migration command or restart the stack.

## Database Access

Open a `psql` shell inside the PostgreSQL container:

```bash
docker compose exec postgres psql -U ela -d embedded_linux_audit
```

Useful tables:

- `devices`
- `device_aliases`
- `terminal_connections`
- `uploads`
- `command_uploads`
- `file_list_entries`
- `grep_matches`
- `symlink_list_entries`
- `efi_variables`
- `uboot_env_candidates`
- `uboot_env_variables`
- `arch_reports`
- `log_events`

Example queries:

```sql
select mac_address, first_seen_at, last_seen_at from devices order by last_seen_at desc;
select d.mac_address, a.alias from device_aliases a join devices d on d.id = a.device_id;
select upload_type, count(*) from uploads group by upload_type order by upload_type;
```

## Health Checks And Sanity Checks

Verify service state:

```bash
docker compose ps
```

Verify the frontend is answering:

```bash
curl -i http://localhost/
```

Verify the upload endpoint is reachable:

```bash
curl -i -X POST \
  -H 'Content-Type: text/plain' \
  --data-binary 'hello' \
  http://localhost/aa:bb:cc:dd:ee:ff/upload/log
```

Verify the terminal endpoint is listening through nginx:

```bash
curl -i http://localhost/terminal/test
```

That request will not complete a WebSocket handshake, but it confirms nginx is
routing the path.

Verify the pcap WebSocket path is routed to the agent API:

```bash
curl -i http://localhost/pcap/aa:bb:cc:dd:ee:ff
```

That request also will not complete a WebSocket handshake, but it should not be
handled by the terminal or GDB services. A real capture stream is started from
the agent with:

```bash
./embedded_linux_audit --output-http http://localhost/upload \
  linux pcap --interface eth0
```

## Resetting The Stack

### Soft Reset

Use this when you want a clean process restart but want to keep all data:

```bash
docker compose down
docker compose up -d
```

### Full Reset

Use this when you want to wipe all persisted state:

```bash
docker compose down -v
docker compose up --build
```

This removes:

- all database rows
- terminal aliases stored in PostgreSQL
- terminal connection history
- upload records and normalized data
- runtime agent artifact files stored in the `agent-data` volume

## Updating The Stack

After code changes:

```bash
docker compose up --build
```

If you only changed one service:

```bash
docker compose build agent-api
docker compose up -d agent-api
```

or:

```bash
docker compose build terminal-api
docker compose up -d terminal-api
```

## Authentication

If you run either API with bearer-token enforcement, the same `ela.key` file
must be available to the service container. The current compose stack does not
mount a production key file by default, so you must add that bind mount or bake
the file into a derived image before enabling `--validate-key`.

Related docs:

- [docs/api/auth.md](/home/nick/Documents/git/embedded_linux_audit/docs/api/auth.md)

## Troubleshooting

### `agent-api` or `terminal-api` exits immediately

Check logs:

```bash
docker compose logs agent-api
docker compose logs terminal-api
```

Common causes:

- PostgreSQL is not healthy yet
- invalid DB credentials
- migration failure
- missing Node dependency inside the image

### `nginx` is up but requests fail

Check:

```bash
docker compose logs nginx
docker compose ps
```

Then confirm upstream services are listening:

```bash
docker compose exec agent-api sh -lc 'ss -lnt'
docker compose exec terminal-api sh -lc 'ss -lnt'
```

### Uploads succeed but expected rows are missing

Inspect the DB directly:

```bash
docker compose exec postgres psql -U ela -d embedded_linux_audit
```

Then query:

```sql
select id, mac_address from devices;
select id, upload_type, api_timestamp from uploads order by id desc limit 20;
```

If the upload type is new, confirm it is included in:

- [api/agent/server.js](/home/nick/Documents/git/embedded_linux_audit/api/agent/server.js)
- [api/lib/db/normalizeUpload.js](/home/nick/Documents/git/embedded_linux_audit/api/lib/db/normalizeUpload.js)

For pcap captures, the database row uses upload type `pcap` and the packet data
is stored as a `.pcap` artifact under the per-device runtime data directory.

### Terminal aliases do not appear

Check:

```sql
select d.mac_address, a.alias
from device_aliases a
join devices d on d.id = a.device_id;
```

If you previously used `ela-aliases.json`, restart `terminal-api` once after the
DB is available so the legacy import path can run.

## Related Files

- [docker-compose.yml](/home/nick/Documents/git/embedded_linux_audit/docker-compose.yml)
- [nginx/docker.conf](/home/nick/Documents/git/embedded_linux_audit/nginx/docker.conf)
- [api/agent/Dockerfile](/home/nick/Documents/git/embedded_linux_audit/api/agent/Dockerfile)
- [api/terminal/Dockerfile](/home/nick/Documents/git/embedded_linux_audit/api/terminal/Dockerfile)
