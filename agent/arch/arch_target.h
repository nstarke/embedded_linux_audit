// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_ARCH_TARGET_H
#define ELA_ARCH_TARGET_H

/* -------------------------------------------------------------------------
 * Compile-time architecture properties derived from the target triple.
 *
 * These values are baked in at build time so they reflect the binary's
 * actual target, not the host running the binary.  The compiler macros used
 * here are defined by GCC and Clang (including Zig cc / LLVM).
 *
 * Shared by the `arch` command (which reports each value individually) and
 * `linux modules buildinfo` (which sends them to the module builder).
 * ---------------------------------------------------------------------- */

/* ISA family ------------------------------------------------------------ */
#if defined(__x86_64__)
#  define ARCH_ISA "x86_64"
#elif defined(__i386__)
#  define ARCH_ISA "x86"
#elif defined(__aarch64__)
#  define ARCH_ISA "aarch64"
#elif defined(__arm__)
#  define ARCH_ISA "arm32"
#elif defined(__mips64)
#  define ARCH_ISA "mips64"
#elif defined(__mips__)
#  define ARCH_ISA "mips"
#elif defined(__powerpc64__)
#  define ARCH_ISA "powerpc64"
#elif defined(__powerpc__)
#  define ARCH_ISA "powerpc"
#elif defined(__riscv)
#  if __riscv_xlen == 64
#    define ARCH_ISA "riscv64"
#  else
#    define ARCH_ISA "riscv32"
#  endif
#else
#  define ARCH_ISA "unknown"
#endif

/* Pointer width → bit size ---------------------------------------------- */
#if defined(__SIZEOF_POINTER__)
#  if __SIZEOF_POINTER__ == 8
#    define ARCH_BITS "64"
#  else
#    define ARCH_BITS "32"
#  endif
#elif defined(__LP64__) || defined(_LP64)
#  define ARCH_BITS "64"
#else
#  define ARCH_BITS "32"
#endif

/* Endianness ------------------------------------------------------------ */
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
#  if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#    define ARCH_ENDIANNESS "big"
#  else
#    define ARCH_ENDIANNESS "little"
#  endif
#elif defined(__BIG_ENDIAN__)
#  define ARCH_ENDIANNESS "big"
#else
#  define ARCH_ENDIANNESS "little"
#endif

#endif
