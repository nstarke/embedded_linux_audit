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
 * kernel.org mirror URL for an upstream release tarball. Served from
 * mirrors.edge.kernel.org (cdn.kernel.org has been unreliable). Tarballs group
 * by directory: `v3.x`, `v4.x`, … but the 2.6 series lives under `v2.6` (2.4
 * under `v2.4`), not `v2.x`.
 * `"3.12.19"` → `.../v3.x/linux-3.12.19.tar.xz`;
 * `"2.6.32"`  → `.../v2.6/linux-2.6.32.tar.xz`.
 */
function kernelTarballUrl(version) {
  const parsed = parseKernelRelease(version);
  if (!parsed || parsed.localVersion) {
    return null;
  }
  const dir = parsed.major === 2
    ? `v2.${parsed.version.split('.')[1]}`
    : `v${parsed.major}.x`;
  return `https://mirrors.edge.kernel.org/pub/linux/kernel/${dir}/linux-${parsed.version}.tar.xz`;
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

/**
 * Parse the config-derived flag tokens the kernel bakes into a vermagic string
 * (from include/linux/vermagic.h + the arch's MODULE_ARCH_VERMAGIC). The first
 * whitespace token is the kernel release; each remaining token maps to a
 * CONFIG_ symbol, so when the device config is unavailable we can still
 * reconstruct the vermagic-affecting parts of a defconfig build.
 *
 *   "3.12.19-rt30 SMP mod_unload ARMv7 p2v8" ->
 *     { smp:true, preempt:false, preemptRt:false, modUnload:true,
 *       modversions:false, armArch:'ARMv7', patchPhysVirt:true }
 *
 * Unknown tokens are ignored. `armArch` is the raw "ARMv<n>" token (or null),
 * which the build script uses to pick an arch-appropriate base defconfig — SMP
 * and the ARMv<n> level are coupled to the CPU/platform, not a lone toggle.
 *
 * @param {string} vermagic
 * @returns {{smp:boolean, preempt:boolean, preemptRt:boolean, modUnload:boolean,
 *   modversions:boolean, armArch:(string|null), patchPhysVirt:boolean}}
 */
function parseVermagicFlags(vermagic) {
  const tokens = String(vermagic || '').trim().split(/\s+/).slice(1);
  const flags = {
    smp: false,
    preempt: false,
    preemptRt: false,
    modUnload: false,
    modversions: false,
    armArch: null,
    patchPhysVirt: false,
  };
  for (const tok of tokens) {
    switch (tok) {
      case 'SMP': flags.smp = true; break;
      case 'preempt': flags.preempt = true; break;
      case 'preempt_rt': flags.preemptRt = true; break;
      case 'mod_unload': flags.modUnload = true; break;
      case 'modversions': flags.modversions = true; break;
      case 'p2v8': flags.patchPhysVirt = true; break;
      default:
        if (/^ARMv\d+$/.test(tok)) {
          flags.armArch = tok;
        }
        break;
    }
  }
  return flags;
}

module.exports = {
  resolveTarget,
  parseKernelRelease,
  kernelTarballUrl,
  compareVermagic,
  parseVermagicFlags,
};
