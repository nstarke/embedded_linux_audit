# Docker Operations Guide

This guide covers how to run, inspect, and maintain the containerized
`embedded_linux_audit` server stack.

## Services

The default [docker-compose.yml](/home/nick/Documents/git/embedded_linux_audit/docker-compose.yml) starts four containers:

- `postgres` - PostgreSQL database
- `agent-api` - HTTP upload and asset-serving API
- `terminal-api` - WebSocket terminal server
- `nginx` - frontend reverse proxy for both APIs

Traffic flow:

- `http://localhost/` -> `agent-api`
- `http://localhost/terminal/<mac>` -> `terminal-api`

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

To compile release binaries locally in Docker and disable GitHub release
downloads for the agent API:

```bash
./nginx/install.sh ela.example.com --compile-locally
```

To set the local release build parallelism explicitly:

```bash
./nginx/install.sh ela.example.com --compile-locally --jobs 8
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

Important database variables used by the APIs:

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
- `ELA_AGENT_SKIP_ASSET_SYNC`
- `ELA_AGENT_REPO`

The bundled agent container starts with `--reuse-last-data-dir`, so container
restarts continue writing runtime artifacts into the latest timestamped
directory already present in the `agent-data` volume instead of creating a new
timestamp on every boot.

Important terminal API variables:

- `ELA_TERMINAL_HOST`
- `ELA_TERMINAL_PORT`
- `ELA_KEY_PATH`

Example override at launch time:

```bash
ELA_DB_PASSWORD=strongpassword docker compose up -d --build
```

## Migrations

The APIs run migrations on startup automatically. The migration runner lives in:

- [api/lib/db/migrate.js](/home/nick/Documents/git/embedded_linux_audit/api/lib/db/migrate.js)

If you need to run migrations manually inside the `agent-api` container:

```bash
docker compose run --rm agent-api node /app/api/lib/db/migrate.js
```

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
