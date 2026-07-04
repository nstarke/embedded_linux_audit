#!/bin/sh
# SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
#
# Compile the kmod/ kernel module against an upstream kernel tree matching a
# target device's kernel, using plain kernel headers (modules_prepare) — no
# buildroot, no full kernel build.
#
# Inputs (env):
#   ELA_KMOD_KERNEL_VERSION  upstream base version, e.g. "6.1.0" or "3.12.19" (required)
#   ELA_KMOD_LOCALVERSION    local suffix to reproduce device vermagic, e.g. "-rt30"
#   ELA_KMOD_ARCH            kernel ARCH=, e.g. "arm64" (required)
#   ELA_KMOD_CROSS_COMPILE   toolchain prefix, e.g. "aarch64-linux-gnu-" (empty for native)
#   ELA_KMOD_CONFIG_PATH     device kernel config (.gz or plain); defconfig when absent
#   ELA_KMOD_SRC_DIR         module sources (dir with Kbuild), default <repo>/kmod
#   ELA_KMOD_OUT_DIR         where ela_kmod.ko + vermagic.txt land (required)
#   ELA_KMOD_CACHE_DIR       tarball + prepared-tree cache, default /var/cache/ela-kmod
#
# Cache layout:
#   $CACHE/tarballs/linux-<ver>.tar.xz
#   $CACHE/trees/<ver>-<arch>-<confighash>/linux-<ver>/   (configured, modules_prepare'd)
#
# The prepared tree is the expensive artifact (minutes); the module compile
# afterward is seconds. Trees are keyed by (version, arch, config hash) so a
# device with a different config never reuses a mismatched tree.

set -eu

log() { echo "[kmod-build] $*"; }
die() { echo "[kmod-build] ERROR: $*" >&2; exit 1; }

KERNEL_VERSION="${ELA_KMOD_KERNEL_VERSION:-}"
LOCALVERSION="${ELA_KMOD_LOCALVERSION:-}"
ARCH="${ELA_KMOD_ARCH:-}"
CROSS_COMPILE="${ELA_KMOD_CROSS_COMPILE:-}"
CONFIG_PATH="${ELA_KMOD_CONFIG_PATH:-}"
OUT_DIR="${ELA_KMOD_OUT_DIR:-}"
CACHE_DIR="${ELA_KMOD_CACHE_DIR:-/var/cache/ela-kmod}"
REPO_ROOT="${ELA_BUILD_REPO_ROOT:-/src}"
SRC_DIR="${ELA_KMOD_SRC_DIR:-$REPO_ROOT/kmod}"
# Vermagic-derived defconfig flags (set by runModuleBuild when the device has a
# vermagic; absent otherwise). Default to empty so `set -u` doesn't abort on the
# no-vermagic / non-ARM paths — empty means "leave the defconfig default".
ELA_KMOD_VM_SMP="${ELA_KMOD_VM_SMP:-}"
ELA_KMOD_VM_PREEMPT="${ELA_KMOD_VM_PREEMPT:-}"
ELA_KMOD_VM_MODULE_UNLOAD="${ELA_KMOD_VM_MODULE_UNLOAD:-}"
ELA_KMOD_VM_PATCH_PHYS_VIRT="${ELA_KMOD_VM_PATCH_PHYS_VIRT:-}"
ELA_KMOD_VM_ARM_ARCH="${ELA_KMOD_VM_ARM_ARCH:-}"

[ -n "$KERNEL_VERSION" ] || die "ELA_KMOD_KERNEL_VERSION is required"
[ -n "$ARCH" ] || die "ELA_KMOD_ARCH is required"
[ -n "$OUT_DIR" ] || die "ELA_KMOD_OUT_DIR is required"
[ -f "$SRC_DIR/Kbuild" ] || die "module source not found at $SRC_DIR"

case "$KERNEL_VERSION" in
  *[!0-9.]*) die "kernel version must be an upstream x.y[.z] release: $KERNEL_VERSION" ;;
esac

MAJOR="${KERNEL_VERSION%%.*}"
TARBALL_URL="https://cdn.kernel.org/pub/linux/kernel/v${MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz"
TARBALL="$CACHE_DIR/tarballs/linux-${KERNEL_VERSION}.tar.xz"

mkdir -p "$CACHE_DIR/tarballs" "$CACHE_DIR/trees" "$OUT_DIR"

# --- 1. Fetch the kernel source tarball (cache hit = no network) -----------
if [ ! -f "$TARBALL" ]; then
    log "downloading $TARBALL_URL"
    curl -fSL --retry 3 -o "$TARBALL.part" "$TARBALL_URL" \
        || die "failed to download kernel $KERNEL_VERSION (air-gapped? pre-seed $TARBALL)"
    mv "$TARBALL.part" "$TARBALL"
else
    log "tarball cache hit: $TARBALL"
fi

# --- 2. Materialize the device kernel config -------------------------------
WORK_CONFIG=""
CONFIG_HASH="defconfig"
if [ -n "$CONFIG_PATH" ]; then
    [ -f "$CONFIG_PATH" ] || die "config not found: $CONFIG_PATH"
    WORK_CONFIG="$(mktemp /tmp/ela-kmod-config.XXXXXX)"
    trap 'rm -f "$WORK_CONFIG"' EXIT INT TERM
    # The agent uploads /proc/config.gz verbatim; accept plain text too.
    if gzip -t "$CONFIG_PATH" 2>/dev/null; then
        gzip -dc "$CONFIG_PATH" >"$WORK_CONFIG"
    else
        cat "$CONFIG_PATH" >"$WORK_CONFIG"
    fi
    grep -q '^CONFIG_' "$WORK_CONFIG" || die "config has no CONFIG_ lines: $CONFIG_PATH"
    CONFIG_HASH="$(sha256sum "$WORK_CONFIG" | cut -c1-16)"
else
    # No device config: the synthesized defconfig is specialized by the
    # vermagic-derived flags/arch, so fold them into the cache key. Otherwise
    # two devices that differ only in (say) SMP would collide on one prepared
    # tree and the second would silently reuse the first one's config.
    VM_SIG="arch=${ELA_KMOD_VM_ARM_ARCH} smp=${ELA_KMOD_VM_SMP} preempt=${ELA_KMOD_VM_PREEMPT} modunload=${ELA_KMOD_VM_MODULE_UNLOAD} p2v=${ELA_KMOD_VM_PATCH_PHYS_VIRT}"
    CONFIG_HASH="defconfig-$(printf '%s' "$VM_SIG" | sha256sum | cut -c1-16)"
fi

TREE_KEY="${KERNEL_VERSION}-${ARCH}-${CONFIG_HASH}"
TREE_PARENT="$CACHE_DIR/trees/$TREE_KEY"
TREE="$TREE_PARENT/linux-$KERNEL_VERSION"
PREPARED_STAMP="$TREE_PARENT/.prepared"

kmake() {
    # LOCALVERSION reproduces the device's release suffix in the built
    # vermagic. Setting it empty also suppresses the "+" localversion the
    # kernel appends when building outside git without CONFIG_LOCALVERSION.
    make -C "$TREE" ARCH="$ARCH" CROSS_COMPILE="$CROSS_COMPILE" \
        LOCALVERSION="$LOCALVERSION" "$@"
}

# --- 3. Unpack + configure + modules_prepare (cached) ----------------------
if [ ! -f "$PREPARED_STAMP" ]; then
    rm -rf "$TREE_PARENT"
    mkdir -p "$TREE_PARENT"
    log "unpacking linux-$KERNEL_VERSION"
    tar -xJf "$TARBALL" -C "$TREE_PARENT"
    [ -d "$TREE" ] || die "tarball did not contain linux-$KERNEL_VERSION/"

    # Old kernels (pre-~4.x) hardcode `#include <linux/compiler-gcc$(GNUC).h>`,
    # a per-GCC-major header that only shipped for the compilers of their era.
    # A modern cross-GCC (e.g. 12) then dies with:
    #   fatal error: linux/compiler-gccN.h: No such file or directory
    # Upstream dropped the per-version split in 4.x and the macros are
    # compatible, so alias the missing header to the newest one the tree ships.
    COMPILER_GCC_DIR="$TREE/include/linux"
    if [ -f "$COMPILER_GCC_DIR/compiler-gcc.h" ]; then
        GCC_MAJOR="$("${CROSS_COMPILE}gcc" -dumpversion 2>/dev/null | cut -d. -f1)"
        case "$GCC_MAJOR" in
          ''|*[!0-9]*) GCC_MAJOR="" ;;  # only trust a clean integer
        esac
        if [ -n "$GCC_MAJOR" ] && [ ! -f "$COMPILER_GCC_DIR/compiler-gcc${GCC_MAJOR}.h" ]; then
            NEWEST=""
            for h in "$COMPILER_GCC_DIR"/compiler-gcc[0-9]*.h; do
                [ -f "$h" ] || continue  # no glob match -> literal pattern, skip
                n="${h##*compiler-gcc}"; n="${n%.h}"
                case "$n" in *[!0-9]*|'') continue ;; esac
                if [ -z "$NEWEST" ] || [ "$n" -gt "$NEWEST_N" ]; then
                    NEWEST="$h"; NEWEST_N="$n"
                fi
            done
            if [ -n "$NEWEST" ]; then
                log "gcc $GCC_MAJOR shim: aliasing $(basename "$NEWEST") -> compiler-gcc${GCC_MAJOR}.h"
                cp "$NEWEST" "$COMPILER_GCC_DIR/compiler-gcc${GCC_MAJOR}.h"
            fi
        fi
    fi

    if [ -n "$WORK_CONFIG" ]; then
        log "configuring from device config"
        cp "$WORK_CONFIG" "$TREE/.config"
        # Settle symbols the device's kernel didn't know about (config from an
        # older/newer minor) with their defaults, non-interactively.
        kmake olddefconfig
    else
        # `make defconfig`. NOTE: on ARM this is versatile_defconfig (ARMv5, UP),
        # where CONFIG_SMP / ARMv7 can't be selected — the flags below are still
        # applied but olddefconfig drops the unsatisfiable ones. Reaching an
        # exact ARMv7/SMP vermagic that way needs multi_v7_defconfig, which drags
        # in the device-tree host tools (scripts/dtc) that don't build under a
        # modern host toolchain on this vintage kernel; exact-vermagic matching
        # is handled downstream by vermagic patching instead.
        log "no device config; using $ARCH defconfig"
        kmake defconfig

        # A defconfig build is best-effort: modules must at least be enabled,
        # and MODVERSIONS off avoids CRC mismatches against the real kernel
        # (we can't reproduce the device's symbol CRCs, so matching that
        # vermagic token would only make loads fail on the CRC check instead).
        "$TREE/scripts/config" --file "$TREE/.config" \
            -e MODULES -d MODVERSIONS -d MODULE_SIG -d MODULE_SIG_FORCE

        # Reconstruct the vermagic-affecting flags the device advertised so the
        # built module's vermagic matches without the full config. An empty env
        # means "unknown" (no device vermagic) -> leave the defconfig default.
        ela_apply_flag() {  # $1 = y|n|"" , $2 = CONFIG symbol
            case "$1" in
                y) "$TREE/scripts/config" --file "$TREE/.config" -e "$2" ;;
                n) "$TREE/scripts/config" --file "$TREE/.config" -d "$2" ;;
            esac
        }
        ela_apply_flag "$ELA_KMOD_VM_SMP" SMP
        ela_apply_flag "$ELA_KMOD_VM_PREEMPT" PREEMPT
        ela_apply_flag "$ELA_KMOD_VM_MODULE_UNLOAD" MODULE_UNLOAD
        if [ "$ARCH" = arm ]; then
            ela_apply_flag "$ELA_KMOD_VM_PATCH_PHYS_VIRT" ARM_PATCH_PHYS_VIRT
        fi
        [ -n "$ELA_KMOD_VM_SMP" ] && log "applied vermagic flags:" \
            "SMP=$ELA_KMOD_VM_SMP PREEMPT=$ELA_KMOD_VM_PREEMPT" \
            "MODULE_UNLOAD=$ELA_KMOD_VM_MODULE_UNLOAD" \
            "ARM_PATCH_PHYS_VIRT=$ELA_KMOD_VM_PATCH_PHYS_VIRT"

        # olddefconfig settles any symbols the forced options pulled in/out.
        kmake olddefconfig
    fi

    grep -q '^CONFIG_MODULES=y' "$TREE/.config" \
        || die "target kernel config does not enable loadable modules"

    log "running modules_prepare (this is the slow step on a cold cache)"
    kmake modules_prepare
    touch "$PREPARED_STAMP"
else
    log "prepared tree cache hit: $TREE_KEY"
fi

# --- 4. Build the module out-of-tree ---------------------------------------
BUILD_DIR="$(mktemp -d /tmp/ela-kmod-build.XXXXXX)"
trap 'rm -rf "$BUILD_DIR"; rm -f "$WORK_CONFIG"' EXIT INT TERM
cp "$SRC_DIR"/* "$BUILD_DIR/"

log "building module for $ARCH against linux-$KERNEL_VERSION"
# Force non-PIC codegen. Distro cross-GCCs (e.g. Debian's) default to -fPIE,
# which emits GOT-based relocations referencing _GLOBAL_OFFSET_TABLE_. A kernel
# module has no GOT, so it then fails to load with:
#   <mod>: Unknown symbol _GLOBAL_OFFSET_TABLE_
# The kernel build only started passing -fno-PIE itself in ~4.9, so pre-4.9
# trees need us to add it. Harmless (redundant) on newer kernels/arches, where
# modules are non-PIC anyway.
kmake M="$BUILD_DIR" modules KCFLAGS="-fno-pic -fno-PIE"

[ -f "$BUILD_DIR/ela_kmod.ko" ] || die "build produced no ela_kmod.ko"

# --- 5. Extract the built vermagic and stage artifacts ---------------------
# modinfo may not exist for foreign ELF targets; scan the .modinfo strings the
# same way the agent does (vermagic=<value>\0).
BUILT_VERMAGIC="$(tr '\0' '\n' <"$BUILD_DIR/ela_kmod.ko" | sed -n 's/^vermagic=//p' | head -n 1)"
[ -n "$BUILT_VERMAGIC" ] || die "could not extract vermagic from built module"

cp "$BUILD_DIR/ela_kmod.ko" "$OUT_DIR/ela_kmod.ko"
printf '%s\n' "$BUILT_VERMAGIC" >"$OUT_DIR/vermagic.txt"

log "built $OUT_DIR/ela_kmod.ko (vermagic: $BUILT_VERMAGIC)"
