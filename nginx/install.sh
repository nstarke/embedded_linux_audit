#!/bin/sh
# Install and start the containerized embedded_linux_audit server stack.
#
# What this script does:
#   1. Verifies Docker and Docker Compose are available
#   2. Optionally uses a caller-provided compose env file
#   3. Builds and starts the PostgreSQL, agent API, terminal API, and nginx containers
#
# Run from anywhere inside a repository checkout:
#   ./nginx/install.sh example.com
#   ./nginx/install.sh example.com --env-file /path/to/ela.env
#   ./nginx/install.sh example.com --no-build
#   ./nginx/install.sh example.com --foreground

set -eu

usage() {
    cat <<'EOF'
Usage: nginx/install.sh [options]

Positional arguments:
  HOSTNAME         Replace example.com in the nginx config template

Options:
  --env-file PATH  Pass an env file to docker compose
  --no-build       Skip image builds and start with existing images
  --foreground     Run docker compose up in the foreground
  --pull           Pull newer base images before starting
  --help           Show this help text
EOF
}

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"
NGINX_TEMPLATE="$REPO_ROOT/nginx/docker.conf"
GENERATED_NGINX_CONF="$REPO_ROOT/nginx/docker.generated.conf"
BUILD=1
DETACH=1
PULL=0
ENV_FILE=""
HOSTNAME=""

while [ "$#" -gt 0 ]; do
    case "$1" in
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

if [ ! -f "$NGINX_TEMPLATE" ]; then
    echo "error: $NGINX_TEMPLATE not found" >&2
    exit 1
fi

if [ -z "$HOSTNAME" ]; then
    echo "error: HOSTNAME is required" >&2
    usage >&2
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

sed "s/example\\.com/$HOSTNAME/g" "$NGINX_TEMPLATE" > "$GENERATED_NGINX_CONF"
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
    echo "Frontend URL: http://$HOSTNAME/"
    echo "Terminal URL base: ws://$HOSTNAME/terminal/<mac>"
    echo "Follow logs with: docker compose -f $COMPOSE_FILE logs -f"
fi
