// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

// Pure mapping/parsing helpers for kernel-module builds. No I/O — everything
// here is unit-testable and shared by runModuleBuild.js (env construction)
// and the client API (request validation before enqueueing).

// Map the agent's compile-time target facts (module-buildinfo isa/bits/
// endianness, from agent/arch/arch_target.h) to the kernel build system's
// ARCH= value and the Debian cross toolchain prefix installed in the builder
// image. Entries are keyed `<isa>:<endianness>`; ISAs whose kernels only come
// in one endianness ignore the endianness key (listed under both).
//
// Unlisted combinations (aarch64 BE, arm32 BE, riscv32) have no packaged
// Debian cross compiler; requests for them are rejected at enqueue time
// rather than failing minutes into a build.
const TARGETS = {
  'x86_64:little': { arch: 'x86_64', crossCompile: 'x86_64-linux-gnu-' },
  'x86:little': { arch: 'i386', crossCompile: 'i686-linux-gnu-' },
  'aarch64:little': { arch: 'arm64', crossCompile: 'aarch64-linux-gnu-' },
  'arm32:little': { arch: 'arm', crossCompile: 'arm-linux-gnueabi-' },
  'mips:big': { arch: 'mips', crossCompile: 'mips-linux-gnu-' },
  'mips:little': { arch: 'mips', crossCompile: 'mipsel-linux-gnu-' },
  'mips64:big': { arch: 'mips', crossCompile: 'mips64-linux-gnuabi64-' },
  'mips64:little': { arch: 'mips', crossCompile: 'mips64el-linux-gnuabi64-' },
  'powerpc:big': { arch: 'powerpc', crossCompile: 'powerpc-linux-gnu-' },
  'powerpc64:big': { arch: 'powerpc', crossCompile: 'powerpc64-linux-gnu-' },
  'powerpc64:little': { arch: 'powerpc', crossCompile: 'powerpc64le-linux-gnu-' },
  'riscv64:little': { arch: 'riscv', crossCompile: 'riscv64-linux-gnu-' },
};

/**
 * Resolve a build target from module-buildinfo facts.
 * @param {{isa?:string, endianness?:string}} buildInfo
 * @returns {{arch:string, crossCompile:string}|null} null when unsupported.
 */
function resolveTarget(buildInfo) {
  const isa = String((buildInfo && buildInfo.isa) || '').toLowerCase();
  const endianness = String((buildInfo && buildInfo.endianness) || '').toLowerCase();
  return TARGETS[`${isa}:${endianness}`] || null;
}

/**
 * Split a kernel release string into the upstream base version and the local
 * suffix. `"3.12.19-rt30"` → `{version:"3.12.19", localVersion:"-rt30"}`;
 * `"6.1.0"` → `{version:"6.1.0", localVersion:""}`. Returns null when no
 * x.y[.z] prefix is present.
 *
 * The base version is what we can fetch from kernel.org; the local suffix is
 * vendor/config territory and is re-applied via LOCALVERSION so the built
 * module's vermagic matches the device's.
 */
function parseKernelRelease(release) {
  const match = /^(\d+)\.(\d+)(?:\.(\d+))?(.*)$/.exec(String(release || '').trim());
  if (!match) {
    return null;
  }
  const [, major, minor, patch, rest] = match;
  // A base version must be followed by nothing or a separator — reject
  // "6.1foo" while accepting "6.1.0-rt30", "6.1.0", and "4.4.0+".
  if (rest && !/^[-+._~]/.test(rest)) {
    return null;
  }
  const version = patch === undefined ? `${major}.${minor}` : `${major}.${minor}.${patch}`;
  return {
    version,
    major: Number.parseInt(major, 10),
    localVersion: rest || '',
  };
}

/**
 * kernel.org CDN URL for an upstream release tarball.
 * `"3.12.19"` → `.../v3.x/linux-3.12.19.tar.xz`.
 */
function kernelTarballUrl(version) {
  const parsed = parseKernelRelease(version);
  if (!parsed || parsed.localVersion) {
    return null;
  }
  return `https://cdn.kernel.org/pub/linux/kernel/v${parsed.major}.x/linux-${parsed.version}.tar.xz`;
}

/**
 * Compare two vermagic strings the way the kernel does for the version part,
 * but report the whole-string result too. Returns:
 *   'match'         — identical strings
 *   'release-match' — first token (kernel release) matches, flags differ
 *   'mismatch'      — different kernel release; loadable only with --force
 */
function compareVermagic(built, wanted) {
  const a = String(built || '').trim();
  const b = String(wanted || '').trim();
  if (!a || !b) {
    return 'mismatch';
  }
  if (a === b) {
    return 'match';
  }
  return a.split(/\s+/)[0] === b.split(/\s+/)[0] ? 'release-match' : 'mismatch';
}

module.exports = {
  resolveTarget,
  parseKernelRelease,
  kernelTarballUrl,
  compareVermagic,
};
