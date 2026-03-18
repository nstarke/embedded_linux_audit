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
#   ./nginx/install.sh example.com --compile-locally
#   ./nginx/install.sh example.com --compile-locally --jobs 8
#   ./nginx/install.sh example.com --foreground

set -eu

usage() {
    cat <<'EOF'
Usage: nginx/install.sh HOSTNAME [options]

Positional arguments:
  HOSTNAME         Hostname substituted into the nginx config (e.g. ela.example.com)

Options:
  --cert PATH           TLS certificate file (PEM); auto-generated self-signed if omitted
  --key  PATH           TLS private key file  (PEM); required when --cert is given
  --github-token TOKEN  GitHub token for downloading release binaries (or set GITHUB_TOKEN env var)
  --env-file PATH       Pass an env file to docker compose
  --no-build            Skip image builds and start with existing images
  --compile-locally     Build release binaries in a Docker builder container and disable GitHub release fetch
  --jobs N              Set release-binary compiler job count (only valid with --compile-locally)
  --foreground          Run docker compose up in the foreground
  --pull                Pull newer base images before starting
  --help                Show this help text

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
COMPILE_LOCALLY=0
COMPILE_JOBS=""
ENV_FILE=""
HOSTNAME=""
TLS_CERT=""
TLS_KEY=""
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
RELEASE_BUILDER_IMAGE="ela-release-builder:local"
RELEASE_BUILDER_DOCKERFILE="$REPO_ROOT/tests/release-builder.Dockerfile"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --github-token)
            shift
            if [ "$#" -eq 0 ]; then
                echo "error: --github-token requires a value" >&2
                exit 1
            fi
            GITHUB_TOKEN="$1"
            ;;
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
        --compile-locally)
            COMPILE_LOCALLY=1
            ;;
        --jobs)
            shift
            if [ "$#" -eq 0 ]; then
                echo "error: --jobs requires an integer value" >&2
                exit 1
            fi
            COMPILE_JOBS="$1"
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

if [ -n "$COMPILE_JOBS" ]; then
    case "$COMPILE_JOBS" in
        ''|*[!0-9]*)
            echo "error: --jobs requires a positive integer" >&2
            exit 1
            ;;
        0)
            echo "error: --jobs must be greater than zero" >&2
            exit 1
            ;;
    esac
fi

if [ -n "$COMPILE_JOBS" ] && [ "$COMPILE_LOCALLY" -ne 1 ]; then
    echo "error: --jobs can only be used with --compile-locally" >&2
    exit 1
fi

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "error: $COMPOSE_FILE not found" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Privileged port capability (ports 80 / 443)
# docker-proxy must have cap_net_bind_service to bind ports below 1024.
# ---------------------------------------------------------------------------
_docker_proxy="$(command -v docker-proxy 2>/dev/null || true)"
if [ -n "$_docker_proxy" ]; then
    if ! getcap "$_docker_proxy" 2>/dev/null | grep -q cap_net_bind_service; then
        echo "Granting cap_net_bind_service to $_docker_proxy ..."
        setcap cap_net_bind_service=+ep "$_docker_proxy" 2>/dev/null || \
            sudo setcap cap_net_bind_service=+ep "$_docker_proxy" || {
                echo "warning: could not set cap_net_bind_service on docker-proxy" >&2
                echo "         Ports 80/443 may be inaccessible." >&2
                echo "         Run manually: sudo setcap cap_net_bind_service=+ep $_docker_proxy" >&2
            }
    fi
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
ELA_DATA_DIR="${ELA_DATA_DIR:-/data/agent}"
if [ ! -d "$ELA_DATA_DIR" ]; then
    echo "Creating agent data directory $ELA_DATA_DIR ..."
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

ELA_RELEASE_BINARIES_DIR="$ELA_DATA_DIR/release_binaries"
mkdir -p "$ELA_RELEASE_BINARIES_DIR"
export ELA_RELEASE_BINARIES_DIR

# ---------------------------------------------------------------------------
# PostgreSQL data directory
# ---------------------------------------------------------------------------
ELA_POSTGRES_DATA_DIR="${ELA_POSTGRES_DATA_DIR:-/data/postgres}"
if [ ! -d "$ELA_POSTGRES_DATA_DIR" ]; then
    echo "Creating PostgreSQL data directory $ELA_POSTGRES_DATA_DIR ..."
    mkdir -p "$ELA_POSTGRES_DATA_DIR" || {
        echo "error: failed to create $ELA_POSTGRES_DATA_DIR" >&2
        echo "       Try: sudo mkdir -p $ELA_POSTGRES_DATA_DIR && sudo chown \$(id -u):\$(id -g) $ELA_POSTGRES_DATA_DIR" >&2
        exit 1
    }
fi
export ELA_POSTGRES_DATA_DIR

# ---------------------------------------------------------------------------
# Socket UID — used inside the terminal-api container to chown the tmux
# socket so the invoking user can attach without sudo.
# ---------------------------------------------------------------------------
_real_user="${SUDO_USER:-$USER}"
ELA_SOCKET_UID="$(id -u "$_real_user" 2>/dev/null || id -u)"
export ELA_SOCKET_UID

# ---------------------------------------------------------------------------
# tmux socket directory for terminal-api
# ---------------------------------------------------------------------------
ELA_TERMINAL_SOCKET_DIR="${ELA_TERMINAL_SOCKET_DIR:-/run/ela-terminal}"
if [ ! -d "$ELA_TERMINAL_SOCKET_DIR" ]; then
    mkdir -p "$ELA_TERMINAL_SOCKET_DIR" || {
        echo "error: failed to create $ELA_TERMINAL_SOCKET_DIR" >&2
        exit 1
    }
    chmod 0755 "$ELA_TERMINAL_SOCKET_DIR"
fi
export ELA_TERMINAL_SOCKET_DIR

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
export GITHUB_TOKEN

if [ "$COMPILE_LOCALLY" -eq 1 ]; then
    export ELA_AGENT_SKIP_ASSET_SYNC=true
    if [ -z "$COMPILE_JOBS" ]; then
        COMPILE_JOBS="$(nproc)"
    fi

    if [ ! -f "$RELEASE_BUILDER_DOCKERFILE" ]; then
        echo "error: $RELEASE_BUILDER_DOCKERFILE not found" >&2
        exit 1
    fi

    if [ "$BUILD" -eq 1 ]; then
        echo "Building local release-binary builder image..."
        docker build -f "$RELEASE_BUILDER_DOCKERFILE" -t "$RELEASE_BUILDER_IMAGE" "$REPO_ROOT"
    elif ! docker image inspect "$RELEASE_BUILDER_IMAGE" >/dev/null 2>&1; then
        echo "error: $RELEASE_BUILDER_IMAGE is not available and --no-build was requested" >&2
        echo "       Re-run without --no-build or pre-build the image with:" >&2
        echo "       docker build -f $RELEASE_BUILDER_DOCKERFILE -t $RELEASE_BUILDER_IMAGE $REPO_ROOT" >&2
        exit 1
    fi

    echo "Compiling release binaries locally into $ELA_RELEASE_BINARIES_DIR ..."
    docker run --rm \
        -v "$REPO_ROOT:/src" \
        -v "$ELA_RELEASE_BINARIES_DIR:/out" \
        -w /src \
        -e RELEASE_BINARIES_DIR=/out \
        "$RELEASE_BUILDER_IMAGE" \
        /bin/bash -lc "git config --global --add safe.directory /src && /bin/bash tests/compile_release_binaries_locally.sh --clean --jobs=\"$COMPILE_JOBS\""
else
    export ELA_AGENT_SKIP_ASSET_SYNC=false
    echo "Using GitHub release asset fetch for agent binaries."
fi

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

echo "Starting database and API containers before nginx..."
if [ "$BUILD" -eq 1 ]; then
    "$@" up -d --build postgres agent-api terminal-api
else
    "$@" up -d postgres agent-api terminal-api
fi

if [ "$DETACH" -eq 1 ]; then
    echo "Restarting nginx after upstream services are ready..."
    "$@" rm -sf nginx >/dev/null 2>&1 || true
    if [ "$BUILD" -eq 1 ]; then
        "$@" up -d --build nginx
    else
        "$@" up -d nginx
    fi
else
    echo "Starting nginx in the foreground after upstream services are ready..."
    "$@" rm -sf nginx >/dev/null 2>&1 || true
    if [ "$BUILD" -eq 1 ]; then
        "$@" up --build nginx
    else
        "$@" up nginx
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
