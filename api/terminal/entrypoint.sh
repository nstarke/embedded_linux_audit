#!/bin/sh
set -e

mkdir -p /run/ela-terminal

# Create socket with world-accessible permissions (0666) so host users
# can attach without needing to be root.
umask 0111

exec tmux -S /run/ela-terminal/tmux.sock \
    new-session -s ela-terminal \
    "node /app/api/terminal/server.js; echo '[ela-terminal exited — press Enter to close]'; read _"
