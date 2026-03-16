# nginx Reverse Proxy Configuration

The example configuration in `nginx/ela.conf` exposes both the agent helper
API and the WebSocket terminal server behind a single frontend.

## Architecture

```
Internet
    ├── HTTP  / WS  (port 80)  ──┐
    └── HTTPS / WSS (port 443) ──┤
                                  ▼
                            nginx  (ela.example.com)
                              ├── /terminal/<mac>  ──► ws://127.0.0.1:8080
                              └── /*               ──► http://127.0.0.1:5000
```

`/terminal/<mac>` is routed to the WebSocket terminal server.  Everything
else is passed to the agent API at its native web root — no path prefix
stripping is needed, so agent API routes work at the same paths they use
when accessed directly.

Both HTTP and HTTPS are served independently.  HTTP is not redirected to
HTTPS so that agents on networks without TLS can still connect using `ws://`
or `http://` URLs.

## Prerequisites

On a fresh nginx install (Debian/Ubuntu), the default site at
`/etc/nginx/sites-enabled/default` also claims `default_server` for ports 80
and 443.  Remove it before deploying `ela.conf`, otherwise nginx will reject
the `default_server` directive with a config-test error:

```sh
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

Once the default site is removed, `ela.conf`'s `default_server` directive
ensures requests by IP address (e.g. `ws://192.168.1.100`) are handled
correctly without needing to add every IP to `server_name`.

## Installation

```sh
# Install nginx config (removes the conflicting default site automatically)
sudo nginx/install.sh

# Place your TLS certificate and key (for wss:// only)
sudo cp your.crt /etc/ssl/certs/ela.example.com.crt
sudo cp your.key /etc/ssl/private/ela.example.com.key
sudo nginx -t && sudo systemctl reload nginx
```

The install script removes `/etc/nginx/sites-enabled/default` before enabling
`ela.conf`.  This is required: the Ubuntu default site also declares
`default_server` for port 80, and because `default` sorts before `ela`
alphabetically, it would win and intercept all IP-based requests — returning
400 for WebSocket upgrades — even with the correct ela config in place.

Edit `ela.conf` to replace `ela.example.com` with your actual hostname before
deploying (optional — the `_` wildcard in `server_name` already handles
IP-based access without a hostname).

## TLS

The config enables TLSv1.2 and TLSv1.3 with strong ciphers.  It also sets:

- `Strict-Transport-Security` (HSTS, 2 years, includeSubDomains)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`

Use a certificate from a trusted CA (e.g. Let's Encrypt) for production.  For
testing with a self-signed certificate, run the agent with `--insecure`.

## Agent API

All agent API routes are served at the web root, identical to direct access:

```
GET  https://ela.example.com/                              →  http://127.0.0.1:5000/
GET  https://ela.example.com/tests/agent/shell/download_tests.sh  →  http://127.0.0.1:5000/tests/agent/shell/download_tests.sh
POST https://ela.example.com/upload                        →  http://127.0.0.1:5000/upload
```

`client_max_body_size` is set to 200 MB to accommodate large binary uploads
(e.g. U-Boot images, option ROMs).

## Terminal WebSocket endpoint (`/terminal/<mac>`)

WebSocket upgrade headers are forwarded:

```nginx
proxy_set_header Upgrade    $http_upgrade;
proxy_set_header Connection "upgrade";
```

`proxy_read_timeout` is set to `120s` — four times the 30-second heartbeat
interval — so idle sessions are not closed by nginx between heartbeats.

The agent connects using the public URL:

```sh
# Plain WebSocket (port 80)
./embedded_linux_audit transfer --remote ws://ela.example.com

# Secure WebSocket (port 443)
./embedded_linux_audit transfer --remote wss://ela.example.com

# Skip TLS certificate verification (self-signed certs, testing only)
./embedded_linux_audit --insecure transfer --remote wss://ela.example.com
```

The agent always appends `/terminal/<mac>` to the base URL before connecting.

## Authorization header forwarding

```nginx
proxy_set_header Authorization $http_authorization;
```

This passes the `Authorization: Bearer <token>` header from the agent through
to both backends.  Each backend validates it independently against its own
`ela.key`.  See [API Key Authentication — server side](auth.md).

## Starting the backends

```sh
# Agent helper API (port 5000)
cd api/agent && npm start

# Terminal server (port 8080)
cd api/terminal && npm start
```

With API key enforcement:

```sh
cd api/agent   && npm run start:secure
cd api/terminal && npm run start:secure
```
