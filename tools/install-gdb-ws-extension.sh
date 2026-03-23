#!/bin/sh
# SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
# Set up the GDB WebSocket extension on an analyst workstation.
#
# What this script does:
#   1. Verifies python3 is available
#   2. Ensures the 'websockets' Python package is installed
#   3. Adds "source .../tools/gdb-ws-insecure.py" to ~/.gdbinit if not present
#
# Run from anywhere inside a repository checkout:
#   ./tools/install-gdb-ws-extension.sh

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
GDB_EXTENSION="$SCRIPT_DIR/gdb-ws-insecure.py"
GDBINIT_FILE="$HOME/.gdbinit"
GDBINIT_LINE="source $GDB_EXTENSION"

# ---------------------------------------------------------------------------
# 1. Verify python3
# ---------------------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is not installed or not on PATH" >&2
    echo "       Install python3 and re-run this script." >&2
    exit 1
fi

PYTHON="$(command -v python3)"
echo "Using python3: $PYTHON"

# ---------------------------------------------------------------------------
# 2. Ensure the 'websockets' package is installed
# ---------------------------------------------------------------------------
if "$PYTHON" -c "import websockets" 2>/dev/null; then
    WS_VERSION="$("$PYTHON" -c "import websockets; print(websockets.__version__)")"
    echo "websockets already installed (version $WS_VERSION)"
else
    echo "websockets not found; installing..."
    if "$PYTHON" -m pip install websockets; then
        WS_VERSION="$("$PYTHON" -c "import websockets; print(websockets.__version__)")"
        echo "websockets installed (version $WS_VERSION)"
    elif "$PYTHON" -m pip install --user websockets; then
        WS_VERSION="$("$PYTHON" -c "import websockets; print(websockets.__version__)")"
        echo "websockets installed (version $WS_VERSION, user install)"
    else
        echo "error: failed to install websockets" >&2
        echo "       Try manually: pip install websockets" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# 3. Add the source line to ~/.gdbinit
# ---------------------------------------------------------------------------
if [ ! -f "$GDB_EXTENSION" ]; then
    echo "error: $GDB_EXTENSION not found" >&2
    exit 1
fi

if grep -qF "$GDBINIT_LINE" "$GDBINIT_FILE" 2>/dev/null; then
    echo "GDB WebSocket extension already present in $GDBINIT_FILE"
else
    printf '%s\n' "$GDBINIT_LINE" >> "$GDBINIT_FILE"
    echo "Added GDB WebSocket extension to $GDBINIT_FILE"
fi

echo
echo "Setup complete. In gdb-multiarch:"
echo "  wss-remote [--insecure] wss://HOST/gdb/out/<32-hex-key>"
