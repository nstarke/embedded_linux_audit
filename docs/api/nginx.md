# nginx Frontend Configuration

The default deployment path now runs nginx inside Docker Compose using
`nginx/docker.conf`. The legacy host-nginx example in `nginx/ela.conf` is still
kept as a reference for non-container deployments, but `nginx/install.sh` now
installs and starts the full Dockerized stack instead of copying a host nginx
site file.

## Docker Architecture

```
Internet
    ├── HTTP  / WS  (port 80)  ──► nginx container
    └── HTTPS / WSS (port 443) ──►     ├── /terminal/<mac>  ──► terminal-api:8080
                                        └── /*               ──► agent-api:5000
```

`/terminal/<mac>` is routed to the WebSocket terminal server. Everything else
is passed to the agent API at its native web root.

Both HTTP (port 80) and HTTPS (port 443) are served independently — plain HTTP
is never redirected to HTTPS so that agents on networks without TLS can
still connect.

## Prerequisites

- Docker Engine with Compose support
- Access to the Docker daemon
- Free listeners on TCP ports `80` and `443`
- `openssl` on the host (only needed when not supplying your own cert)
- `docker-proxy` with `cap_net_bind_service` (see below)

## Privileged port capability

Docker binds host ports through `docker-proxy`, which must hold
`cap_net_bind_service` to use ports below 1024 (80 and 443).
`install.sh` applies this automatically, but you can set or verify it
manually:

```sh
# Grant the capability
sudo setcap cap_net_bind_service=+ep $(command -v docker-proxy)

# Verify
getcap $(command -v docker-proxy)
# → /usr/bin/docker-proxy cap_net_bind_service=+ep
```

The capability must be re-applied after Docker is upgraded since package
upgrades replace the binary.

## Installation

```sh
./nginx/install.sh ela.example.com
```

If `--cert` and `--key` are not supplied, a 10-year self-signed certificate is
generated automatically and stored in `nginx/ssl/` (gitignored). On subsequent
runs the existing cert is reused; delete `nginx/ssl/` to force regeneration.

To supply your own certificate:

```sh
./nginx/install.sh ela.example.com --cert /path/to/ela.crt --key /path/to/ela.key
```

Common options:

- `./nginx/install.sh ela.example.com --env-file /path/to/ela.env`
- `./nginx/install.sh ela.example.com --no-build`
- `./nginx/install.sh ela.example.com --foreground`

The installer runs `docker compose up` against the repository's
[docker-compose.yml](/home/nick/Documents/git/embedded_linux_audit/docker-compose.yml)
and starts:

- `postgres`
- `agent-api`
- `terminal-api`
- `nginx`

It also generates a temporary nginx config for Compose by replacing
`example.com` in [nginx/docker.conf](/home/nick/Documents/git/embedded_linux_audit/nginx/docker.conf)
with the `HOSTNAME` argument using `sed`.

## Agent API

All agent API routes are served at the web root:

```
GET  http://localhost/                                     →  agent-api:5000/
GET  http://localhost/tests/agent/shell/download_tests.sh →  agent-api:5000/tests/agent/shell/download_tests.sh
POST http://localhost/upload                              →  agent-api:5000/upload
```

`client_max_body_size` remains `200m` in the bundled Docker nginx config.

## Terminal WebSocket endpoint (`/terminal/<mac>`)

The agent connects using the public URL:

```sh
./embedded_linux_audit transfer --remote ws://localhost
```

The agent always appends `/terminal/<mac>` to the base URL before connecting.

## Authorization header forwarding

```nginx
proxy_set_header Authorization $http_authorization;
```

This passes the `Authorization: Bearer <token>` header from the agent through
to both backends.  Each backend validates it independently against its own
`ela.key`.  See [API Key Authentication — server side](auth.md).

## Legacy Host nginx

If you need a non-container deployment, `nginx/ela.conf` is still available as
a reference reverse-proxy config for host-installed nginx in front of
host-installed agent and terminal services.
