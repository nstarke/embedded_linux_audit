#!/bin/sh

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SCRIPT_NAME="$(basename "$0")"

WEB_SERVER=""
OUTPUT_DIRECTORY=""
TEMP_OUTPUT_DIRECTORY=""
ISA=""

# Remove stale temporary download directories from previous runs.
for stale_dir in /tmp/download_tests_output.*; do
    [ -d "$stale_dir" ] || continue
    rm -rf -- "$stale_dir"
done

usage() {
    echo "usage: $0 --webserver <url> --isa <arch> [--output-directory <path>]"
    echo "   or: $0 --webserver=<url> --isa=<arch> [--output-directory=<path>]"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --webserver)
            if [ "$#" -lt 2 ]; then
                echo "error: --webserver requires a value"
                usage
                exit 2
            fi
            WEB_SERVER="$2"
            shift 2
            ;;
        --webserver=*)
            WEB_SERVER="${1#*=}"
            shift
            ;;
        --output-directory)
            if [ "$#" -lt 2 ]; then
                echo "error: --output-directory requires a value"
                usage
                exit 2
            fi
            OUTPUT_DIRECTORY="$2"
            shift 2
            ;;
        --output-directory=*)
            OUTPUT_DIRECTORY="${1#*=}"
            shift
            ;;
        --isa)
            if [ "$#" -lt 2 ]; then
                echo "error: --isa requires a value"
                usage
                exit 2
            fi
            ISA="$2"
            shift 2
            ;;
        --isa=*)
            ISA="${1#*=}"
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1"
            usage
            exit 2
            ;;
    esac
done

if [ -z "$WEB_SERVER" ]; then
    echo "error: --webserver is required"
    usage
    exit 2
fi

if [ -z "$ISA" ]; then
    echo "error: --isa is required"
    usage
    exit 2
fi

BASE_URL="${WEB_SERVER%/}"

if command -v curl >/dev/null 2>&1 || which curl >/dev/null 2>&1; then
    downloader="curl"
elif command -v wget >/dev/null 2>&1 || which wget >/dev/null 2>&1; then
    downloader="wget"
else
    echo "error: neither curl nor wget is installed"
    exit 1
fi

fetch_to_file() {
    url="$1"
    out_file="$2"

    if [ "$downloader" = "curl" ]; then
        curl -fsSL "$url" -o "$out_file"
    else
        wget -qO "$out_file" "$url"
    fi
}

INDEX_FILE="$(mktemp /tmp/download_tests_index.XXXXXX)"
SCRIPT_LIST_FILE="$(mktemp /tmp/download_tests_list.XXXXXX)"

if [ -n "$OUTPUT_DIRECTORY" ]; then
    mkdir -p "$OUTPUT_DIRECTORY"
    DEST_DIR="$OUTPUT_DIRECTORY"
else
    TEMP_OUTPUT_DIRECTORY="$(mktemp -d /tmp/download_tests_output.XXXXXX)"
    DEST_DIR="$TEMP_OUTPUT_DIRECTORY"
fi

cleanup() {
    rm -f "$INDEX_FILE" "$SCRIPT_LIST_FILE"
}
trap cleanup EXIT HUP INT TERM

echo "output directory: $DEST_DIR"

echo "fetching index: $BASE_URL/"
fetch_to_file "$BASE_URL/" "$INDEX_FILE"

sed 's/[^A-Za-z0-9_./-]/\
/g' "$INDEX_FILE" | \
    grep '^/*tests/.*\.sh$' | \
    sed 's#^/*##' | sort -u >"$SCRIPT_LIST_FILE"

if [ ! -s "$SCRIPT_LIST_FILE" ]; then
    echo "error: no test shell scripts found in index at $BASE_URL/"
    exit 1
fi

while IFS= read -r rel_path; do
    script_file="$(basename "$rel_path")"

    if [ "$script_file" = "$SCRIPT_NAME" ]; then
        continue
    fi

    url="$BASE_URL/$rel_path"
    dest="$DEST_DIR/$script_file"

    echo "downloading $url -> $dest"

    fetch_to_file "$url" "$dest"
done <"$SCRIPT_LIST_FILE"

AUDIT_BINARY_NAME="uboot_audit-$ISA"
AUDIT_BINARY_URL="$BASE_URL/$AUDIT_BINARY_NAME"
AUDIT_BINARY_TMP="$(mktemp /tmp/uboot_audit.XXXXXX)"
AUDIT_BINARY_DEST="/tmp/uboot_audit"

echo "downloading $AUDIT_BINARY_URL -> $AUDIT_BINARY_DEST"
fetch_to_file "$AUDIT_BINARY_URL" "$AUDIT_BINARY_TMP"
chmod +x "$AUDIT_BINARY_TMP"
mv -f "$AUDIT_BINARY_TMP" "$AUDIT_BINARY_DEST"

echo "done"
if [ -n "$TEMP_OUTPUT_DIRECTORY" ]; then
    echo "files written to temporary directory: $TEMP_OUTPUT_DIRECTORY"
fi
