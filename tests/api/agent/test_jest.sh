#!/bin/sh

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

cd "$REPO_ROOT"

if [ ! -x node_modules/.bin/jest ]; then
    echo "error: jest is not installed; run 'npm ci' at the repository root first" >&2
    exit 1
fi

node_modules/.bin/jest --runInBand tests/unit/api/agent tests/unit/api/lib
