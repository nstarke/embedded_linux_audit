#!/bin/sh
# Grant tmux server-access to every member of the 'ela' group.
# Runs as ExecStartPost in ela-terminal.service after the tmux server is up.
# Requires tmux >= 3.2.
#
# To allow a user to attach:
#   usermod -aG ela <username>
# then restart the service (or re-run this script manually).

SOCKET=/run/ela-terminal/tmux.sock

members=$(getent group ela | cut -d: -f4 | tr ',' '\n')

if [ -z "$members" ]; then
    echo "grant-tmux-access: no members in the 'ela' group, skipping" >&2
    exit 0
fi

for user in $members; do
    [ -z "$user" ] && continue
    /usr/bin/tmux -S "$SOCKET" server-access -a "$user"
    echo "grant-tmux-access: granted tmux access to $user"
done
