#!/bin/sh
# Install the ela nginx reverse-proxy configuration.
#
# What this script does:
#   1. Copies ela.conf to /etc/nginx/sites-available/ela
#   2. Removes the Ubuntu default site, which conflicts with default_server
#   3. Creates the sites-enabled symlink
#   4. Tests the configuration and reloads nginx
#
# Run as root or with sudo.

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
CONF_SRC="$SCRIPT_DIR/ela.conf"
CONF_DEST="/etc/nginx/sites-available/ela"
CONF_LINK="/etc/nginx/sites-enabled/ela"
DEFAULT_LINK="/etc/nginx/sites-enabled/default"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root or with sudo" >&2
    exit 1
fi

if [ ! -f "$CONF_SRC" ]; then
    echo "error: $CONF_SRC not found" >&2
    exit 1
fi

# Step 1: install the config file
cp "$CONF_SRC" "$CONF_DEST"
echo "Installed $CONF_DEST"

# Step 2: remove the default site — it claims default_server for port 80/443
# and sorts before 'ela' alphabetically, stealing all IP-based requests.
if [ -e "$DEFAULT_LINK" ] || [ -L "$DEFAULT_LINK" ]; then
    rm -f "$DEFAULT_LINK"
    echo "Removed $DEFAULT_LINK (was conflicting with default_server)"
fi

# Step 3: enable the ela config
if [ ! -e "$CONF_LINK" ]; then
    ln -s "$CONF_DEST" "$CONF_LINK"
    echo "Created symlink $CONF_LINK"
else
    echo "$CONF_LINK already exists"
fi

# Step 4: test and reload
if nginx -t; then
    nginx -s reload
    echo "nginx reloaded successfully"
else
    echo "error: nginx config test failed — not reloading" >&2
    exit 1
fi
