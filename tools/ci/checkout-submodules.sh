#!/usr/bin/env bash
set -euo pipefail

# Unit tests stub TPM calls and only need its headers. None of these builds
# consume U-Boot's source tree or optional nested dependency test fixtures.
paths=(third_party/libcsv third_party/json-c third_party/tpm2-tss)
case "${1:?expected unit, static or native}" in
  unit) ;;
  static|native)
    paths+=(third_party/curl third_party/openssl third_party/libubootenv
      third_party/zlib third_party/libefivar third_party/wolfssl
      third_party/libssh third_party/libxml2 third_party/libpcap)
    if [[ "$1" == native ]]; then
      paths+=(third_party/ncurses third_party/readline)
    fi
    ;;
  *) echo "Unknown dependency profile: $1" >&2; exit 1 ;;
esac
git submodule update --init --depth=1 --jobs=4 -- "${paths[@]}"
