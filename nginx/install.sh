#!/bin/sh
# Install and start the containerized embedded_linux_audit server stack.
#
# What this script does:
#   1. Verifies Docker and Docker Compose are available
#   2. Ensures TLS cert/key are available (provided or auto-generated self-signed)
#   3. Builds and starts the PostgreSQL, agent API, terminal API, and nginx containers
#
# Both HTTP (port 80/WS) and HTTPS (port 443/WSS) are always served.
# HTTP is never redirected to HTTPS — agents without TLS can still connect.
#
# Run from anywhere inside a repository checkout:
#   ./nginx/install.sh example.com
#   ./nginx/install.sh example.com --cert /path/to/ela.crt --key /path/to/ela.key
#   ./nginx/install.sh example.com --env-file /path/to/ela.env
#   ./nginx/install.sh example.com --no-build
#   ./nginx/install.sh example.com --foreground

set -eu

usage() {
    cat <<'EOF'
Usage: nginx/install.sh HOSTNAME [options]

Positional arguments:
  HOSTNAME         Hostname substituted into the nginx config (e.g. ela.example.com)

Options:
  --cert PATH      TLS certificate file (PEM); auto-generated self-signed if omitted
  --key  PATH      TLS private key file  (PEM); required when --cert is given
  --env-file PATH  Pass an env file to docker compose
  --no-build       Skip image builds and start with existing images
  --foreground     Run docker compose up in the foreground
  --pull           Pull newer base images before starting
  --help           Show this help text

Both HTTP (port 80 / WS) and HTTPS (port 443 / WSS) are always enabled.
HTTP is not redirected to HTTPS.
EOF
}

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"
NGINX_TLS_TEMPLATE="$REPO_ROOT/nginx/docker-tls.conf"
GENERATED_NGINX_CONF="$REPO_ROOT/nginx/docker.generated.conf"
SSL_DIR="$REPO_ROOT/nginx/ssl"
BUILD=1
DETACH=1
PULL=0
ENV_FILE=""
HOSTNAME=""
TLS_CERT=""
TLS_KEY=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --cert)
            shift
            if [ "$#" -eq 0 ]; then
                echo "error: --cert requires a path" >&2
                exit 1
            fi
            TLS_CERT="$1"
            ;;
        --key)
            shift
            if [ "$#" -eq 0 ]; then
                echo "error: --key requires a path" >&2
                exit 1
            fi
            TLS_KEY="$1"
            ;;
        --env-file)
            shift
            if [ "$#" -eq 0 ]; then
                echo "error: --env-file requires a path" >&2
                exit 1
            fi
            ENV_FILE="$1"
            ;;
        --no-build)
            BUILD=0
            ;;
        --foreground)
            DETACH=0
            ;;
        --pull)
            PULL=1
            ;;
        --help)
            usage
            exit 0
            ;;
        -*)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [ -n "$HOSTNAME" ]; then
                echo "error: unexpected extra argument: $1" >&2
                usage >&2
                exit 1
            fi
            HOSTNAME="$1"
            ;;
    esac
    shift
done

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "error: $COMPOSE_FILE not found" >&2
    exit 1
fi

if [ ! -f "$NGINX_TLS_TEMPLATE" ]; then
    echo "error: $NGINX_TLS_TEMPLATE not found" >&2
    exit 1
fi

if [ -z "$HOSTNAME" ]; then
    echo "error: HOSTNAME is required" >&2
    usage >&2
    exit 1
fi

# Validate explicit TLS arguments if provided
if [ -n "$TLS_CERT" ] && [ -z "$TLS_KEY" ]; then
    echo "error: --cert requires --key" >&2
    exit 1
fi
if [ -n "$TLS_KEY" ] && [ -z "$TLS_CERT" ]; then
    echo "error: --key requires --cert" >&2
    exit 1
fi
if [ -n "$TLS_CERT" ] && [ ! -f "$TLS_CERT" ]; then
    echo "error: cert file not found: $TLS_CERT" >&2
    exit 1
fi
if [ -n "$TLS_KEY" ] && [ ! -f "$TLS_KEY" ]; then
    echo "error: key file not found: $TLS_KEY" >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is not installed or not on PATH" >&2
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "error: docker compose is not available" >&2
    exit 1
fi

if [ -n "$ENV_FILE" ] && [ ! -f "$ENV_FILE" ]; then
    echo "error: env file not found: $ENV_FILE" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Data directory
# ---------------------------------------------------------------------------
ELA_DATA_DIR="${ELA_DATA_DIR:-/data}"
if [ ! -d "$ELA_DATA_DIR" ]; then
    echo "Creating data directory $ELA_DATA_DIR ..."
    mkdir -p "$ELA_DATA_DIR" || {
        echo "error: failed to create $ELA_DATA_DIR" >&2
        echo "       Try: sudo mkdir -p $ELA_DATA_DIR && sudo chown \$(id -u):\$(id -g) $ELA_DATA_DIR" >&2
        exit 1
    }
    _real_user="${SUDO_USER:-$USER}"
    if [ -n "$_real_user" ] && [ "$_real_user" != "root" ]; then
        chown "$_real_user" "$ELA_DATA_DIR" 2>/dev/null || true
    fi
fi
export ELA_DATA_DIR

# ---------------------------------------------------------------------------
# TLS certificate resolution
# ---------------------------------------------------------------------------
# If --cert/--key were not supplied, reuse previously generated self-signed
# certs if they exist, otherwise generate new ones with openssl.
if [ -z "$TLS_CERT" ]; then
    mkdir -p "$SSL_DIR"
    TLS_CERT="$SSL_DIR/ela.crt"
    TLS_KEY="$SSL_DIR/ela.key"

    if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then
        if ! command -v openssl >/dev/null 2>&1; then
            echo "error: openssl is required to generate a self-signed certificate" >&2
            echo "       Install openssl or supply --cert and --key" >&2
            exit 1
        fi
        echo "Generating self-signed TLS certificate for $HOSTNAME ..."
        _openssl_cnf=$(mktemp)
        cat > "$_openssl_cnf" <<OPENSSLEOF
[req]
distinguished_name = req_dn
x509_extensions    = v3_req
prompt             = no
[req_dn]
CN = $HOSTNAME
[v3_req]
subjectAltName = DNS:$HOSTNAME,IP:127.0.0.1
OPENSSLEOF
        openssl req -x509 -newkey rsa:2048 \
            -keyout "$TLS_KEY" \
            -out    "$TLS_CERT" \
            -days   3650 \
            -nodes \
            -config "$_openssl_cnf"
        rm -f "$_openssl_cnf"
        if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then
            echo "error: openssl failed to generate certificate" >&2
            exit 1
        fi
        # Ensure the invoking user (not root) owns the files so docker compose
        # can read them when run without sudo.
        _real_user="${SUDO_USER:-$USER}"
        if [ -n "$_real_user" ] && [ "$_real_user" != "root" ]; then
            chown "$_real_user" "$TLS_CERT" "$TLS_KEY" 2>/dev/null || true
        fi
        chmod 644 "$TLS_CERT"
        chmod 600 "$TLS_KEY"
        echo "  cert: $TLS_CERT"
        echo "  key:  $TLS_KEY"
    else
        echo "Reusing existing TLS certificate: $TLS_CERT"
    fi
fi

export ELA_TLS_CERT="$TLS_CERT"
export ELA_TLS_KEY="$TLS_KEY"

# Generate nginx config with hostname substituted
sed "s/example\\.com/$HOSTNAME/g" "$NGINX_TLS_TEMPLATE" > "$GENERATED_NGINX_CONF"
export ELA_NGINX_CONF_PATH="$GENERATED_NGINX_CONF"

set -- docker compose -f "$COMPOSE_FILE"
if [ -n "$ENV_FILE" ]; then
    set -- "$@" --env-file "$ENV_FILE"
fi

if [ "$PULL" -eq 1 ]; then
    echo "Pulling newer images..."
    "$@" pull
fi

if [ "$DETACH" -eq 1 ]; then
    if [ "$BUILD" -eq 1 ]; then
        echo "Building and starting embedded_linux_audit containers in the background..."
        "$@" up -d --build
    else
        echo "Starting embedded_linux_audit containers in the background..."
        "$@" up -d
    fi
else
    if [ "$BUILD" -eq 1 ]; then
        echo "Building and starting embedded_linux_audit containers in the foreground..."
        "$@" up --build
    else
        echo "Starting embedded_linux_audit containers in the foreground..."
        "$@" up
    fi
fi

if [ "$DETACH" -eq 1 ]; then
    echo
    echo "Stack status:"
    "$@" ps
    echo
    echo "Frontend URL (HTTP):  http://$HOSTNAME/"
    echo "Frontend URL (HTTPS): https://$HOSTNAME/"
    echo "Terminal URL base:    ws://$HOSTNAME/terminal/<mac>"
    echo "Terminal URL base:    wss://$HOSTNAME/terminal/<mac>"
    echo "Follow logs with: docker compose -f $COMPOSE_FILE logs -f"
fi
