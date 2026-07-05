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
    # `rev` bumps whenever the config recipe below changes, so a recipe change
    # invalidates cached prepared trees instead of silently reusing a stale one.
    VM_SIG="rev=2 arch=${ELA_KMOD_VM_ARM_ARCH} smp=${ELA_KMOD_VM_SMP} preempt=${ELA_KMOD_VM_PREEMPT} modunload=${ELA_KMOD_VM_MODULE_UNLOAD} p2v=${ELA_KMOD_VM_PATCH_PHYS_VIRT}"
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
    #
    # HOSTCFLAGS=-fcommon: modern host GCC (>= 10) defaults to -fno-common, which
    # breaks the bundled dtc host tool with "multiple definition of `yylloc`"
    # (its lexer and parser are separate translation units). Device-tree configs
    # (multi_v7_defconfig) pull dtc into modules_prepare, so force -fcommon.
    # Harmless for the other host tools; host code is build-time only.
    #
    # KCFLAGS=-fno-pic -fno-PIE: distro cross-GCCs default to -fPIE. That emits
    # GOT relocations a kernel module can't resolve (Unknown symbol
    # _GLOBAL_OFFSET_TABLE_), and on x86_64 it outright conflicts with the
    # kernel's -mcmodel=kernel even in modules_prepare ("code model kernel does
    # not support PIC mode"). Old kernels (< 4.9) don't add -fno-PIE themselves,
    # so force it for ALL target compilation. Harmless where already non-PIC.
    make -C "$TREE" ARCH="$ARCH" CROSS_COMPILE="$CROSS_COMPILE" \
        LOCALVERSION="$LOCALVERSION" HOSTCFLAGS="-O2 -fcommon" \
        KCFLAGS="-fno-pic -fno-PIE" "$@"
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
        # Base defconfig. On ARM `make defconfig` is versatile (ARMv5, UP). An
        # ARMv7 device needs multi_v7_defconfig (SMP, ARMv7) — but multi_v7 is a
        # kitchen sink of real SoC platforms that force-select features the
        # target may not have (L2 outer cache, HIGHMEM, unwind), each leaking a
        # symbol the device kernel may not export. So for ARMv7 we take multi_v7
        # for its working core (SMP, timers, ARMv7) and strip it down to the bare
        # ARCH_VIRT machine (no L2), then apply universal-safe hardening. This
        # maximizes the set of kernels the module will load on. multi_v7 also
        # drags in device-tree, whose dtc host tool needs the HOSTCFLAGS=-fcommon
        # fix in kmake() to link under a modern host GCC.
        # Base defconfig per arch. Pick the most generic/portable option; the
        # universal-safe hardening below then normalizes the ABI-affecting bits.
        # arm64/x86/riscv have a single generic defconfig; MIPS and PowerPC are
        # machine-fragmented (like ARM) so we take a common baseline and rely on
        # per-device tuning if a symbol leak surfaces.
        DEFCONFIG_TARGET=defconfig
        STRIP_TO_VIRT=
        case "$ARCH" in
        arm)
            if [ "$ELA_KMOD_VM_ARM_ARCH" = ARMv7 ]; then
                DEFCONFIG_TARGET=multi_v7_defconfig
                STRIP_TO_VIRT=1
            fi
            ;;
        arm64)  DEFCONFIG_TARGET=defconfig ;;         # generic, SMP, no highmem
        x86_64) DEFCONFIG_TARGET=x86_64_defconfig ;;  # generic PC, SMP
        i386)   DEFCONFIG_TARGET=i386_defconfig ;;    # SMP-capable; highmem off below
        mips)
            # No single generic MIPS defconfig; malta (QEMU) is the closest to a
            # portable baseline and supports both endiannesses.
            DEFCONFIG_TARGET=malta_defconfig
            ;;
        powerpc)
            # 32- vs 64-bit is chosen by the toolchain prefix.
            case "$CROSS_COMPILE" in
            *powerpc64*) DEFCONFIG_TARGET=pseries_defconfig ;;  # 64-bit, SMP
            *)           DEFCONFIG_TARGET=ppc44x_defconfig ;;   # 32-bit baseline
            esac
            ;;
        riscv)  DEFCONFIG_TARGET=defconfig ;;         # generic, SMP (>=4.15 only)
        esac
        log "no device config; using $ARCH $DEFCONFIG_TARGET"
        kmake "$DEFCONFIG_TARGET"

        cfg() { "$TREE/scripts/config" --file "$TREE/.config" "$@"; }

        if [ -n "$STRIP_TO_VIRT" ]; then
            # Disable every SoC/board platform except ARCH_VIRT (a bare ARMv7 SMP
            # machine with no L2 controller). Dropping the ~80 platform symbols
            # removes the selects that pull in OUTER_CACHE and specific L2 cache
            # controllers. Helper ARCH_* symbols (ARCH_HAS_*, ARCH_SUPPORTS_*,
            # the multiplatform core, VIRT) are preserved so the tree still
            # builds and SMP/timers stay wired.
            log "stripping multi_v7 platforms down to ARCH_VIRT"
            _keep='ARCH_MULTIPLATFORM|ARCH_MULTI_V6|ARCH_MULTI_V7|ARCH_MULTI_V6_V7|ARCH_VIRT'
            _helper='ARCH_(HAS|SUPPORTS|WANT|WANTS|HAVE|MIGHT_HAVE|NR|SELECT|USES|REQUIRE|DMA|FLATMEM|SPARSEMEM|BINFMT|MTD|SUSPEND|HIBERNATION|NO|CLOCKSOURCE|OPTIONAL|PROVIDES)'
            for _s in $(grep -oE '^CONFIG_(ARCH|SOC|MACH)_[A-Z0-9_]+=y' "$TREE/.config" \
                        | sed 's/^CONFIG_//; s/=y//' \
                        | grep -vE "^($_keep)\$" | grep -vE "^$_helper"); do
                cfg -d "$_s"
            done
        fi

        # Modules must be enabled; MODVERSIONS off (we can't reproduce the
        # device's symbol CRCs, so a matching modversions token would only make
        # loads fail on the CRC check instead); signing off.
        cfg -e MODULES -d MODVERSIONS -d MODULE_SIG -d MODULE_SIG_FORCE

        # Universal-safe hardening: these options change the binary layout of
        # core structs (mutex/spinlock/list) or gate lockdep bookkeeping. All
        # OFF matches the common production-kernel case; ON would make the
        # module ABI-incompatible (the SMP-vs-UP mutex mismatch that crashed
        # alloc was exactly this class of problem).
        cfg -d DEBUG_SPINLOCK -d DEBUG_MUTEXES -d DEBUG_LOCK_ALLOC \
            -d PROVE_LOCKING -d LOCKDEP -d DEBUG_LIST -d DEBUG_PREEMPT \
            -d DEBUG_ATOMIC_SLEEP -d TRACE_IRQFLAGS -d DEBUG_INFO

        # Vermagic-affecting flags read off the device vermagic (empty => leave
        # default). These must match or the module is ABI-incompatible.
        ela_apply_flag() {  # $1 = y|n|"" , $2 = CONFIG symbol
            case "$1" in
                y) cfg -e "$2" ;;
                n) cfg -d "$2" ;;
            esac
        }
        ela_apply_flag "$ELA_KMOD_VM_SMP" SMP
        ela_apply_flag "$ELA_KMOD_VM_PREEMPT" PREEMPT
        ela_apply_flag "$ELA_KMOD_VM_MODULE_UNLOAD" MODULE_UNLOAD
        if [ "$ARCH" = arm ]; then
            ela_apply_flag "$ELA_KMOD_VM_PATCH_PHYS_VIRT" ARM_PATCH_PHYS_VIRT
            # No ARM EH unwind tables: CONFIG_ARM_UNWIND makes modules reference
            # __aeabi_unwind_cpp_pr0, exported only by kernels using the EABI
            # unwinder. Frame-pointer kernels don't export it. A module with no
            # unwind tables loads on both.
            cfg -d ARM_UNWIND -e FRAME_POINTER
            # No HIGHMEM: it pulls in kmap/kunmap imports that only resolve on a
            # HIGHMEM kernel. Off => kmap inlines to a direct lowmem access,
            # loading on both (reads target lowmem RAM).
            cfg -d HIGHMEM
            # No outer L2 cache: the generic outer_cache inlines reference the
            # `outer_cache` global; SoCs without an L2 controller don't export
            # it. Our accesses never need outer-cache maintenance.
            cfg -d CACHE_L2X0 -d OUTER_CACHE
            # ARM (not Thumb-2) instruction set: a Thumb-2 module won't load on a
            # kernel whose vermagic carries no "thumb2" token, and vice versa.
            cfg -d THUMB2_KERNEL
        fi
        if [ "$ARCH" = i386 ]; then
            # 32-bit x86 enables HIGHMEM (HIGHMEM4G/64G), which pulls in the same
            # kmap/kunmap imports ARM does. Off => lowmem-only access, loads on
            # both; our reads target lowmem RAM.
            cfg -d HIGHMEM4G -d HIGHMEM64G -e NOHIGHMEM
        fi
        if [ "$ARCH" = mips ]; then
            # Endianness is NOT in the vermagic — it's the ELF byte order, and a
            # wrong-endian module won't load. The base defconfig (malta) defaults
            # to little-endian regardless of the toolchain, so force the config's
            # endianness to match the target (inferred from the cross prefix:
            # mipsel/mips64el => little, mips/mips64 => big).
            case "$CROSS_COMPILE" in
            *mipsel*|*mips64el*) cfg -d CPU_BIG_ENDIAN -e CPU_LITTLE_ENDIAN ;;
            *)                   cfg -e CPU_BIG_ENDIAN -d CPU_LITTLE_ENDIAN ;;
            esac
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
    # PowerPC modules link against arch/powerpc/lib/crtsavres.o (GCC register
    # save/restore stubs). modules_prepare doesn't build it, so the module link
    # fails with "cannot find crtsavres.o" — build it explicitly.
    if [ "$ARCH" = powerpc ]; then
        kmake arch/powerpc/lib/crtsavres.o
    fi
    touch "$PREPARED_STAMP"
else
    log "prepared tree cache hit: $TREE_KEY"
fi

# --- 4. Build the module out-of-tree ---------------------------------------
BUILD_DIR="$(mktemp -d /tmp/ela-kmod-build.XXXXXX)"
trap 'rm -rf "$BUILD_DIR"; rm -f "$WORK_CONFIG"' EXIT INT TERM
cp "$SRC_DIR"/* "$BUILD_DIR/"

log "building module for $ARCH against linux-$KERNEL_VERSION"
# KCFLAGS=-fno-pic -fno-PIE is applied by kmake() for all target compilation.
kmake M="$BUILD_DIR" modules

[ -f "$BUILD_DIR/ela_kmod.ko" ] || die "build produced no ela_kmod.ko"

# --- 5. Extract the built vermagic and stage artifacts ---------------------
# modinfo may not exist for foreign ELF targets; scan the .modinfo strings the
# same way the agent does (vermagic=<value>\0).
BUILT_VERMAGIC="$(tr '\0' '\n' <"$BUILD_DIR/ela_kmod.ko" | sed -n 's/^vermagic=//p' | head -n 1)"
[ -n "$BUILT_VERMAGIC" ] || die "could not extract vermagic from built module"

cp "$BUILD_DIR/ela_kmod.ko" "$OUT_DIR/ela_kmod.ko"
printf '%s\n' "$BUILT_VERMAGIC" >"$OUT_DIR/vermagic.txt"

log "built $OUT_DIR/ela_kmod.ko (vermagic: $BUILT_VERMAGIC)"
