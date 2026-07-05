'use strict';

const {
  resolveTarget,
  parseKernelRelease,
  kernelTarballUrl,
  compareVermagic,
  parseVermagicFlags,
} = require('../../../../api/builder/kernelTarget');

describe('kernelTarget', () => {
  // ── resolveTarget ──────────────────────────────────────────────────────

  test('maps buildinfo facts to kernel ARCH and cross prefix', () => {
    expect(resolveTarget({ isa: 'x86_64', endianness: 'little' }))
      .toEqual({ arch: 'x86_64', crossCompile: 'x86_64-linux-gnu-' });
    expect(resolveTarget({ isa: 'aarch64', endianness: 'little' }))
      .toEqual({ arch: 'arm64', crossCompile: 'aarch64-linux-gnu-' });
    expect(resolveTarget({ isa: 'arm32', endianness: 'little' }))
      .toEqual({ arch: 'arm', crossCompile: 'arm-linux-gnueabi-' });
    expect(resolveTarget({ isa: 'mips', endianness: 'big' }))
      .toEqual({ arch: 'mips', crossCompile: 'mips-linux-gnu-' });
    expect(resolveTarget({ isa: 'mips', endianness: 'little' }))
      .toEqual({ arch: 'mips', crossCompile: 'mipsel-linux-gnu-' });
    expect(resolveTarget({ isa: 'powerpc64', endianness: 'little' }))
      .toEqual({ arch: 'powerpc', crossCompile: 'powerpc64le-linux-gnu-' });
    expect(resolveTarget({ isa: 'riscv64', endianness: 'little' }))
      .toEqual({ arch: 'riscv', crossCompile: 'riscv64-linux-gnu-' });
  });

  test('is case-insensitive', () => {
    expect(resolveTarget({ isa: 'AArch64', endianness: 'Little' }))
      .toEqual({ arch: 'arm64', crossCompile: 'aarch64-linux-gnu-' });
  });

  test('returns null for unsupported or missing targets', () => {
    expect(resolveTarget({ isa: 'aarch64', endianness: 'big' })).toBeNull();
    expect(resolveTarget({ isa: 'arm32', endianness: 'big' })).toBeNull();
    expect(resolveTarget({ isa: 'riscv32', endianness: 'little' })).toBeNull();
    expect(resolveTarget({ isa: 'unknown', endianness: 'little' })).toBeNull();
    expect(resolveTarget({})).toBeNull();
    expect(resolveTarget(null)).toBeNull();
  });

  // ── parseKernelRelease ─────────────────────────────────────────────────

  test('splits release into upstream version and local suffix', () => {
    expect(parseKernelRelease('3.12.19-rt30'))
      .toEqual({ version: '3.12.19', major: 3, localVersion: '-rt30' });
    expect(parseKernelRelease('6.1.0'))
      .toEqual({ version: '6.1.0', major: 6, localVersion: '' });
    expect(parseKernelRelease('6.1'))
      .toEqual({ version: '6.1', major: 6, localVersion: '' });
    expect(parseKernelRelease('4.4.0+'))
      .toEqual({ version: '4.4.0', major: 4, localVersion: '+' });
    expect(parseKernelRelease('5.15.0-91-generic'))
      .toEqual({ version: '5.15.0', major: 5, localVersion: '-91-generic' });
  });

  test('rejects unparseable releases', () => {
    expect(parseKernelRelease('')).toBeNull();
    expect(parseKernelRelease(null)).toBeNull();
    expect(parseKernelRelease('kernel')).toBeNull();
    expect(parseKernelRelease('6')).toBeNull();
    expect(parseKernelRelease('6.1foo')).toBeNull();
  });

  // ── kernelTarballUrl ───────────────────────────────────────────────────

  test('builds the kernel.org mirror URL for an upstream version', () => {
    expect(kernelTarballUrl('3.12.19'))
      .toBe('https://mirrors.edge.kernel.org/pub/linux/kernel/v3.x/linux-3.12.19.tar.xz');
    expect(kernelTarballUrl('6.1.0'))
      .toBe('https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.1.0.tar.xz');
    // The 2.6 series lives under v2.6, not v2.x.
    expect(kernelTarballUrl('2.6.32'))
      .toBe('https://mirrors.edge.kernel.org/pub/linux/kernel/v2.6/linux-2.6.32.tar.xz');
  });

  test('refuses local-suffixed or invalid versions', () => {
    expect(kernelTarballUrl('3.12.19-rt30')).toBeNull();
    expect(kernelTarballUrl('nope')).toBeNull();
  });

  // ── compareVermagic ────────────────────────────────────────────────────

  test('classifies vermagic comparison results', () => {
    const device = '3.12.19-rt30 SMP mod_unload ARMv7';
    expect(compareVermagic(device, device)).toBe('match');
    expect(compareVermagic('3.12.19-rt30 preempt mod_unload ARMv7', device)).toBe('release-match');
    expect(compareVermagic('3.12.19 SMP mod_unload ARMv7', device)).toBe('mismatch');
    expect(compareVermagic('', device)).toBe('mismatch');
    expect(compareVermagic(device, '')).toBe('mismatch');
  });

  // ── parseVermagicFlags ─────────────────────────────────────────────────

  test('reads config-derived flags off a vermagic string', () => {
    expect(parseVermagicFlags('3.12.19-rt30 SMP mod_unload ARMv7 p2v8')).toEqual({
      smp: true,
      preempt: false,
      preemptRt: false,
      modUnload: true,
      modversions: false,
      armArch: 'ARMv7',
      patchPhysVirt: true,
    });
  });

  test('detects preempt, modversions, and a non-SMP ARMv5 target', () => {
    expect(parseVermagicFlags('4.4.0 preempt modversions ARMv5')).toMatchObject({
      smp: false,
      preempt: true,
      modversions: true,
      modUnload: false,
      armArch: 'ARMv5',
      patchPhysVirt: false,
    });
  });

  test('drops the release token and ignores unknown tokens', () => {
    // First token (the release) must not be mistaken for a flag, and an
    // x86_64-style vermagic carries no ARM arch token.
    const f = parseVermagicFlags('5.15.0-generic SMP mod_unload modversions');
    expect(f.smp).toBe(true);
    expect(f.modUnload).toBe(true);
    expect(f.modversions).toBe(true);
    expect(f.armArch).toBeNull();
  });

  test('empty / missing vermagic yields all-false flags', () => {
    const empty = {
      smp: false,
      preempt: false,
      preemptRt: false,
      modUnload: false,
      modversions: false,
      armArch: null,
      patchPhysVirt: false,
    };
    expect(parseVermagicFlags('')).toEqual(empty);
    expect(parseVermagicFlags(null)).toEqual(empty);
  });
});
