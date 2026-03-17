#!/bin/sh
mkdir -p /run/ela-terminal

# Start node inside a detached tmux session using a named socket.
# The socket is created with 0666 so any host user can attach without sudo.
tmux -S /run/ela-terminal/tmux.sock \
    new-session -d -s ela-terminal \
    "exec node /app/api/terminal/server.js"

chmod 0666 /run/ela-terminal/tmux.sock
# Hand socket ownership to the invoking host user so they can attach
# without sudo.  ELA_SOCKET_UID is set by install.sh to the real user's UID.
if [ -n "${ELA_SOCKET_UID:-}" ] && [ "$ELA_SOCKET_UID" != "0" ]; then
    chown "$ELA_SOCKET_UID" /run/ela-terminal/tmux.sock 2>/dev/null || true
fi

# Kill the tmux session cleanly on SIGTERM/SIGINT (docker stop).
trap 'tmux -S /run/ela-terminal/tmux.sock kill-session -t ela-terminal 2>/dev/null; exit 0' TERM INT

# Keep the container alive until the session ends.
while tmux -S /run/ela-terminal/tmux.sock has-session -t ela-terminal 2>/dev/null; do
    sleep 2 &
    wait $!
done
