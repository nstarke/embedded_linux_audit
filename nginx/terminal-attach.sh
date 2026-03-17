#!/bin/sh
# Attach to the ela-terminal tmux session running inside the terminal-api container.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/../docker-compose.yml"
exec docker compose -f "$COMPOSE_FILE" exec terminal-api \
    tmux -S /run/ela-terminal/tmux.sock attach -t ela-terminal
