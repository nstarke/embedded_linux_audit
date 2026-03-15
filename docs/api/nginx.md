# nginx Reverse Proxy Configuration

The example configuration in `nginx/ela.conf` exposes both the agent helper
API and the WebSocket terminal server behind a single HTTPS frontend.

## Architecture

```
Internet
    │  HTTPS / WSS (port 443)
    ▼
  nginx  (ela.example.com)
    ├── /api/agent/    ──► http://127.0.0.1:5000   (api/agent Express server)
    └── /api/terminal/ ──► ws://127.0.0.1:8080    (api/terminal WebSocket server)
```

Plain HTTP (port 80) is redirected to HTTPS.

## Installation

```sh
# Copy the config
cp nginx/ela.conf /etc/nginx/sites-available/ela
ln -s /etc/nginx/sites-available/ela /etc/nginx/sites-enabled/ela

# Place your TLS certificate and key
cp your.crt /etc/ssl/certs/ela.example.com.crt
cp your.key /etc/ssl/private/ela.example.com.key

# Test and reload
nginx -t && systemctl reload nginx
```

Edit `ela.conf` to replace `ela.example.com` with your actual hostname before
deploying.

## TLS

The config enables TLSv1.2 and TLSv1.3 with strong ciphers.  It also sets:

- `Strict-Transport-Security` (HSTS, 2 years, includeSubDomains)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`

Use a certificate from a trusted CA (e.g. Let's Encrypt) for production.  For
testing with a self-signed certificate, run the agent with `--insecure`.

## Agent API endpoint (`/api/agent/`)

Requests to `/api/agent/` have the prefix stripped before forwarding:

```
GET  https://ela.example.com/api/agent/          →  http://127.0.0.1:5000/
POST https://ela.example.com/api/agent/upload    →  http://127.0.0.1:5000/upload
```

`client_max_body_size` is set to 200 MB to accommodate large binary uploads
(e.g. U-Boot images, option ROMs).

## Terminal WebSocket endpoint (`/api/terminal/`)

WebSocket upgrade headers are forwarded:

```nginx
proxy_set_header Upgrade    $http_upgrade;
proxy_set_header Connection "upgrade";
```

`proxy_read_timeout` is set to `120s` — four times the 30-second heartbeat
interval — so idle sessions are not closed by nginx between heartbeats.

The agent connects using the public WSS URL:

```sh
./embedded_linux_audit transfer --remote wss://ela.example.com/api/terminal
```

nginx strips `/api/terminal/` and proxies to `ws://127.0.0.1:8080/terminal/<mac>`.

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
