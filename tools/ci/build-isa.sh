#!/usr/bin/env bash
set -euo pipefail

isa="${1:?expected ISA}"
IFS=',' read -ra targets <<< "${2:?expected compiler targets}"
export CFLAGS= CPPFLAGS= CXXFLAGS= LDFLAGS=
mkdir -p "api/data/release_binaries/$isa" "dist/$isa" .cache/ci

# A successful fallback is remembered only inside an exact recipe cache.
if [[ "${ELA_DEPENDENCY_CACHE_HIT:-}" == true && -f .cache/ci/target ]]; then
  cached_target=$(cat .cache/ci/target)
  for candidate in "${targets[@]}"; do
    if [[ "$candidate" == "$cached_target" ]]; then
      targets=("$cached_target" "${targets[@]}")
      break
    fi
  done
fi

declare -A attempted=()
for target in "${targets[@]}"; do
  [[ -z "${attempted[$target]:-}" ]] || continue
  attempted[$target]=1
  echo "Building $isa with $target"
  make clean-app
  # efivar uses an in-source archive shared between targets. Never cache it.
  rm -f third_party/libefivar/.ela-build-*
  compiler="zig cc -target $target"
  # Match the local release builder's baseline ISA on older PowerPC cores.
  if [[ "$isa" == powerpc-be ]]; then compiler+=' -mcpu=ppc'; fi
  args=(JOBS="${JOBS:-$(nproc)}" ELA_USE_READLINE=0
    CMAKE_C_COMPILER="$(command -v zig)" CMAKE_C_COMPILER_ARG1=cc
    CMAKE_C_COMPILER_TARGET="$target" CC="$compiler")
  if [[ "${ELA_DEPENDENCY_CACHE_HIT:-}" == true ]]; then
    # The exact cache key includes Makefile content. A fresh checkout's mtime
    # must not invalidate libcurl when that content is unchanged.
    args+=(-o Makefile)
  fi
  if make static "${args[@]}" &&
     make build-unit-agent-c "${args[@]}" LDFLAGS=-static \
       UNIT_TEST_CC="$compiler" \
       UNIT_TEST_CFLAGS='-O2 -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE' \
       UNIT_TEST_LDFLAGS=-static; then
    cp embedded_linux_audit "api/data/release_binaries/$isa/ela-$isa"
    if [[ "$isa" == powerpc-le ]]; then
      cp embedded_linux_audit "api/data/release_binaries/$isa/ela-powerpc64-le"
    fi
    cp generated/agent_unit_tests "dist/$isa/agent_unit_tests-$isa"
    printf '%s\n' "$target" > .cache/ci/target
    exit 0
  fi
  echo "Target failed: $target" >&2
done
echo "All compiler targets failed for $isa" >&2
exit 1
