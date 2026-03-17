#!/bin/sh
mkdir -p /run/ela-terminal

# Start node inside a detached tmux session using a named socket.
# The socket is created with 0666 so any host user can attach without sudo.
tmux -S /run/ela-terminal/tmux.sock \
    new-session -d -s ela-terminal \
    "node /app/api/terminal/server.js; echo '[ela-terminal exited — press Enter to close]'; read _"

chmod 0666 /run/ela-terminal/tmux.sock

# Kill the tmux session cleanly on SIGTERM/SIGINT (docker stop).
trap 'tmux -S /run/ela-terminal/tmux.sock kill-session -t ela-terminal 2>/dev/null; exit 0' TERM INT

# Keep the container alive until the session ends.
while tmux -S /run/ela-terminal/tmux.sock has-session -t ela-terminal 2>/dev/null; do
    sleep 2 &
    wait $!
done
