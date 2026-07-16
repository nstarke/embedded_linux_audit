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
  --env-file PATH       Pass an env file to docker compose
  --db-host HOST        Use an EXTERNAL PostgreSQL at HOST instead of the bundled
                        container (the bundled postgres container is not started)
  --db-port PORT        External PostgreSQL port (default 5432)
  --db-name NAME        Database name (default embedded_linux_audit)
  --db-user USER        Database user (default ela)
  --db-password PASS    Database password (default ela)
  --no-build            Skip image builds and start with existing images
  --compile-locally     Pre-build the shared release-binary pool in a Docker builder container
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
COMPOSE_BUNDLED_DB_FILE="$REPO_ROOT/docker-compose.override.yml"
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
DB_HOST=""
DB_PORT=""
DB_NAME=""
DB_USER=""
DB_PASSWORD=""
RELEASE_BUILDER_IMAGE="ela-release-builder:local"
RELEASE_BUILDER_DOCKERFILE="$REPO_ROOT/tests/release-builder.Dockerfile"
DOCKER_RUN_UID="$(id -u)"
DOCKER_RUN_GID="$(id -g)"

copy_compiled_release_binaries() {
    src_root="$1"
    copied_count=0

    for src_path in "$src_root"/*/ela-*; do
        [ -f "$src_path" ] || continue
        file_name="$(basename "$src_path")"
        cp "$src_path" "$src_root/$file_name"
        copied_count=$((copied_count + 1))
        echo "Copied $(basename "$(dirname "$src_path")")/$file_name into $src_root/$file_name"
    done

    if [ "$copied_count" -eq 0 ]; then
        echo "error: local release compile finished but no binaries were copied into $src_root" >&2
        return 1
    fi
}

# Upsert NAME=VALUE into an env file (create it if missing), replacing any
# existing NAME= line. Docker Compose reads this file, so a value persisted here
# survives fresh shells and container recreates. Best-effort: returns non-zero
# (without side effects) if the file cannot be written — callers must guard the
# call (e.g. with `if`) so this never aborts the installer under `set -e`.
persist_env_var() {
    _pev_name="$1"
    _pev_value="$2"
    _pev_file="$3"
    _pev_tmp="${_pev_file}.tmp.$$"

    # Subshell with stderr silenced so a failed redirection (unwritable dir)
    # produces no shell error text — callers report a clearer warning instead.
    if (
        {
            if [ -f "$_pev_file" ]; then
                grep -v "^${_pev_name}=" "$_pev_file" 2>/dev/null || true
            fi
            printf '%s=%s\n' "$_pev_name" "$_pev_value"
        } > "$_pev_tmp"
    ) 2>/dev/null && mv "$_pev_tmp" "$_pev_file" 2>/dev/null; then
        return 0
    fi
    rm -f "$_pev_tmp" 2>/dev/null || true
    return 1
}

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
        --db-host)
            shift
            if [ "$#" -eq 0 ]; then
                echo "error: --db-host requires a value" >&2
                exit 1
            fi
            DB_HOST="$1"
            ;;
        --db-port)
            shift
            if [ "$#" -eq 0 ]; then
                echo "error: --db-port requires a value" >&2
                exit 1
            fi
            DB_PORT="$1"
            ;;
        --db-name)
            shift
            if [ "$#" -eq 0 ]; then
                echo "error: --db-name requires a value" >&2
                exit 1
            fi
            DB_NAME="$1"
            ;;
        --db-user)
            shift
            if [ "$#" -eq 0 ]; then
                echo "error: --db-user requires a value" >&2
                exit 1
            fi
            DB_USER="$1"
            ;;
        --db-password)
            shift
            if [ "$#" -eq 0 ]; then
                echo "error: --db-password requires a value" >&2
                exit 1
            fi
            DB_PASSWORD="$1"
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
# Database target: bundled PostgreSQL container (default) vs external host.
# Passing --db-host selects an external server; the bundled postgres container
# is then not defined or started.  The other --db-* flags customize the
# connection (and the bundled container's credentials when bundled).
# ---------------------------------------------------------------------------
if [ -n "$DB_HOST" ]; then
    EXTERNAL_DB=1
    export ELA_DB_HOST="$DB_HOST"
else
    EXTERNAL_DB=0
fi
[ -n "$DB_PORT" ] && export ELA_DB_PORT="$DB_PORT"
[ -n "$DB_NAME" ] && export ELA_DB_NAME="$DB_NAME"
[ -n "$DB_USER" ] && export ELA_DB_USER="$DB_USER"
[ -n "$DB_PASSWORD" ] && export ELA_DB_PASSWORD="$DB_PASSWORD"

if [ "$EXTERNAL_DB" -eq 0 ] && [ ! -f "$COMPOSE_BUNDLED_DB_FILE" ]; then
    echo "error: $COMPOSE_BUNDLED_DB_FILE not found (needed for the bundled database)" >&2
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
# PostgreSQL data directory (bundled database only)
# ---------------------------------------------------------------------------
if [ "$EXTERNAL_DB" -eq 0 ]; then
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
else
    echo "Using external PostgreSQL at $ELA_DB_HOST; bundled database container will not be started."
fi

# ---------------------------------------------------------------------------
# Redis data directory (build-job queue broker)
# ---------------------------------------------------------------------------
ELA_REDIS_DATA_DIR="${ELA_REDIS_DATA_DIR:-/data/redis}"
if [ ! -d "$ELA_REDIS_DATA_DIR" ]; then
    echo "Creating Redis data directory $ELA_REDIS_DATA_DIR ..."
    mkdir -p "$ELA_REDIS_DATA_DIR" || {
        echo "error: failed to create $ELA_REDIS_DATA_DIR" >&2
        echo "       Try: sudo mkdir -p $ELA_REDIS_DATA_DIR && sudo chown \$(id -u):\$(id -g) $ELA_REDIS_DATA_DIR" >&2
        exit 1
    }
fi
export ELA_REDIS_DATA_DIR

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

if [ "$COMPILE_LOCALLY" -eq 1 ]; then
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

    # Fix any root-owned build artifacts left by older builds that ran without --user.
    # Run as root inside the builder image so we can chown without sudo on the host.
    docker run --rm \
        -v "$REPO_ROOT:/src" \
        "$RELEASE_BUILDER_IMAGE" \
        /bin/sh -c '
            for d in /src/generated /src/third_party/openssl/build* \
                      /src/third_party/curl/build* /src/third_party/json-c/build* \
                      /src/third_party/libssh/build* /src/third_party/libubootenv/build* \
                      /src/third_party/tpm2-tss/build* /src/third_party/wolfssl/build* \
                      /src/third_party/zlib/build*; do
                [ -e "$d" ] || continue
                owner=$(stat -c "%u" "$d" 2>/dev/null || echo "")
                [ "$owner" = "0" ] && chown -R '"$DOCKER_RUN_UID:$DOCKER_RUN_GID"' "$d" 2>/dev/null || true
            done
        ' 2>/dev/null || true

    echo "Compiling release binaries locally into $ELA_RELEASE_BINARIES_DIR ..."
    docker run --rm \
        --user "$DOCKER_RUN_UID:$DOCKER_RUN_GID" \
        -v "$REPO_ROOT:/src" \
        -v "$ELA_RELEASE_BINARIES_DIR:/out" \
        -w /src \
        -e HOME=/tmp/ela-release-builder-home \
        -e RELEASE_BINARIES_DIR=/out \
        "$RELEASE_BUILDER_IMAGE" \
        /bin/bash -lc "mkdir -p \"\$HOME\" && git config --global --add safe.directory '*' && /bin/bash tests/compile_release_binaries_locally.sh --clean --jobs=\"$COMPILE_JOBS\""

    # The helper API serves binaries from the top-level release_binaries
    # directory, while the local compiler writes /out/<isa>/ela-<isa>.
    copy_compiled_release_binaries "$ELA_RELEASE_BINARIES_DIR"
else
    echo "Per-user agent binaries are built when you create a user (tools/add-user-key.js)."
fi

# Generate nginx config with hostname substituted
sed "s/example\\.com/$HOSTNAME/g" "$NGINX_TLS_TEMPLATE" > "$GENERATED_NGINX_CONF"
export ELA_NGINX_CONF_PATH="$GENERATED_NGINX_CONF"

# Base terminal-API WS URL baked into per-user agent launchers (via
# add-user-key) so a dropped launcher auto-connects to this server on a bare run.
# Defaults to wss://<hostname>; override by exporting ELA_SERVER_URL before
# running the installer.
ELA_SERVER_URL="${ELA_SERVER_URL:-wss://$HOSTNAME}"
export ELA_SERVER_URL
echo "Per-user launchers will embed terminal-API URL: $ELA_SERVER_URL"

# Persist ELA_SERVER_URL into the env file Compose reads, so `add-user-key` (run
# later — possibly from a fresh shell or after a container recreate) still sees
# the URL and bakes it into each user's launcher. Default to <repo>/.env when no
# --env-file was given. This is best-effort: the value is already exported for
# this run, so a write failure must not abort the install.
ENV_FILE="${ENV_FILE:-$REPO_ROOT/.env}"
if persist_env_var ELA_SERVER_URL "$ELA_SERVER_URL" "$ENV_FILE"; then
    echo "Persisted ELA_SERVER_URL to $ENV_FILE"
else
    echo "warning: could not write $ENV_FILE — ELA_SERVER_URL is set for this run"
    echo "         only. Later 'add-user-key' runs may need ELA_SERVER_URL exported,"
    echo "         or use tools/rebuild-launchers.js to apply it to existing users."
fi

# The installer passes -f explicitly, which suppresses Compose's automatic
# docker-compose.override.yml merge, so the bundled-DB overlay is listed
# explicitly. External mode uses the base file only (no postgres service).
set -- docker compose -f "$COMPOSE_FILE"
if [ "$EXTERNAL_DB" -eq 0 ]; then
    set -- "$@" -f "$COMPOSE_BUNDLED_DB_FILE"
fi
# Only hand Compose the env file when it actually exists, so a failed/absent
# persist above doesn't turn into a "env file not found" error.
if [ -f "$ENV_FILE" ]; then
    set -- "$@" --env-file "$ENV_FILE"
fi

# Services to start before nginx; the bundled postgres only when not external.
# redis (queue broker) and builder (binary build worker) are always started.
# ghidra-worker consumes the ghidra-analysis queue (rootfs remote-copy +
# decompile); omitting it leaves those jobs stuck 'queued' with no consumer.
APP_SERVICES="redis builder agent-api client-api terminal-api gdb-api ghidra-worker"
if [ "$EXTERNAL_DB" -eq 0 ]; then
    CORE_SERVICES="postgres $APP_SERVICES"
else
    CORE_SERVICES="$APP_SERVICES"
fi

if [ "$PULL" -eq 1 ]; then
    echo "Pulling newer images..."
    "$@" pull
fi

echo "Starting database and API containers before nginx..."
if [ "$BUILD" -eq 1 ]; then
    "$@" up -d --build $CORE_SERVICES
else
    "$@" up -d $CORE_SERVICES
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

# ---------------------------------------------------------------------------
# GDB WebSocket extension — add to the invoking user's ~/.gdbinit so that
# `wss-remote [--insecure] wss://...` is available in every gdb-multiarch
# session without a manual `source` step.
# ---------------------------------------------------------------------------
_real_user="${SUDO_USER:-$USER}"
_real_home="$(getent passwd "$_real_user" 2>/dev/null | cut -d: -f6 || eval echo "~$_real_user")"
GDBINIT_FILE="$_real_home/.gdbinit"
GDBINIT_LINE="source $REPO_ROOT/tools/gdb-ws-insecure.py"

if [ -n "$_real_home" ] && [ "$_real_home" != "/" ]; then
    if grep -qF "$GDBINIT_LINE" "$GDBINIT_FILE" 2>/dev/null; then
        echo "GDB WebSocket extension already present in $GDBINIT_FILE"
    else
        printf '%s\n' "$GDBINIT_LINE" >> "$GDBINIT_FILE"
        echo "Added GDB WebSocket extension to $GDBINIT_FILE"
        echo "  In gdb-multiarch: wss-remote [--insecure] wss://$HOSTNAME/gdb/out/<key>"
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
    echo "PCAP capture stream:  ws://$HOSTNAME/pcap/<mac>"
    echo "PCAP capture stream:  wss://$HOSTNAME/pcap/<mac>"
    echo "GDB tunnel (agent):   linux gdbserver tunnel [--insecure] <PID> wss://$HOSTNAME"
    echo "GDB tunnel (GDB):     wss-remote [--insecure] wss://$HOSTNAME/gdb/out/<key>"
    echo "Follow logs with: $* logs -f"
fi
