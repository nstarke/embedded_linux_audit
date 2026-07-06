'use strict';

const { patchVermagic } = require('../../../../api/lib/vermagicPatch');

// Build a minimal but valid ELF32 LE relocatable object with sections laid out
// as: [ehdr][.modinfo][.text][.shstrtab][section-header table]. .text and the
// shdr table sit AFTER .modinfo so resizing .modinfo must shift them — exactly
// the surgery patchVermagic performs.
function buildElf(modinfoStr) {
  const EHDR = 52;
  const SHENT = 40;
  const modinfo = Buffer.from(modinfoStr, 'ascii');
  const text = Buffer.from('ABCDEFGH', 'ascii');
  const shstr = Buffer.from('\0.modinfo\0.text\0.shstrtab\0', 'ascii');

  const miOff = EHDR;
  const textOff = miOff + modinfo.length;
  const shstrOff = textOff + text.length;
  const shoff = shstrOff + shstr.length;
  const total = shoff + SHENT * 4;

  const buf = Buffer.alloc(total);
  // e_ident
  buf.writeUInt32LE(0x464c457f, 0);
  buf[4] = 1; // 32-bit
  buf[5] = 1; // little-endian
  buf[6] = 1; // version
  buf.writeUInt16LE(1, 16); // e_type = REL
  buf.writeUInt16LE(40, 18); // e_machine = ARM
  buf.writeUInt32LE(1, 20); // e_version
  buf.writeUInt32LE(shoff, 0x20); // e_shoff
  buf.writeUInt16LE(EHDR, 0x28); // e_ehsize
  buf.writeUInt16LE(SHENT, 0x2e); // e_shentsize
  buf.writeUInt16LE(4, 0x30); // e_shnum
  buf.writeUInt16LE(3, 0x32); // e_shstrndx

  modinfo.copy(buf, miOff);
  text.copy(buf, textOff);
  shstr.copy(buf, shstrOff);

  const sh = (i, { name = 0, type = 0, off = 0, size = 0, align = 1 }) => {
    const b = shoff + i * SHENT;
    buf.writeUInt32LE(name, b + 0);
    buf.writeUInt32LE(type, b + 4);
    buf.writeUInt32LE(off, b + 16);
    buf.writeUInt32LE(size, b + 20);
    buf.writeUInt32LE(align, b + 32);
  };
  sh(0, {}); // NULL
  sh(1, { name: 1, type: 1, off: miOff, size: modinfo.length }); // .modinfo
  sh(2, { name: 10, type: 1, off: textOff, size: text.length }); // .text
  sh(3, { name: 16, type: 3, off: shstrOff, size: shstr.length }); // .shstrtab
  return buf;
}

// Independent parser (does not share code with patchVermagic) to read back the
// vermagic value and a named section's bytes, so the test truly validates the
// produced ELF rather than trusting the module's own view.
function parseElf(buf) {
  const shoff = buf.readUInt32LE(0x20);
  const shnum = buf.readUInt16LE(0x30);
  const shstrndx = buf.readUInt16LE(0x32);
  const shdr = (i) => shoff + i * 40;
  const shstrOff = buf.readUInt32LE(shdr(shstrndx) + 16);
  const readStr = (at) => {
    let e = at;
    while (buf[e] !== 0) e += 1;
    return buf.toString('ascii', at, e);
  };
  const sections = {};
  for (let i = 0; i < shnum; i += 1) {
    const name = readStr(shstrOff + buf.readUInt32LE(shdr(i)));
    sections[name] = {
      off: buf.readUInt32LE(shdr(i) + 16),
      size: buf.readUInt32LE(shdr(i) + 20),
    };
  }
  const mi = sections['.modinfo'];
  const blob = buf.slice(mi.off, mi.off + mi.size);
  let vermagic = null;
  for (const entry of blob.toString('ascii').split('\0')) {
    if (entry.startsWith('vermagic=')) vermagic = entry.slice('vermagic='.length);
  }
  return { sections, vermagic, shoff };
}

describe('patchVermagic', () => {
  test('replaces a longer vermagic, resizing .modinfo and shifting later sections', () => {
    const elf = buildElf('license=GPL\0vermagic=1.0 SMP p2v8\0');
    const before = parseElf(elf);

    const target = '1.0 SMP preempt ARMv7 p2v8'; // longer than the original
    const out = patchVermagic(elf, target);
    const after = parseElf(out);

    expect(after.vermagic).toBe(target);
    // .text content survived the shift intact...
    expect(out.slice(after.sections['.text'].off, after.sections['.text'].off + 8).toString())
      .toBe('ABCDEFGH');
    // ...at a shifted offset, and the shdr table + .modinfo size grew too.
    expect(after.sections['.text'].off).toBeGreaterThan(before.sections['.text'].off);
    expect(after.shoff).toBeGreaterThan(before.shoff);
    expect(after.sections['.modinfo'].size).toBeGreaterThan(before.sections['.modinfo'].size);
  });

  test('a shorter vermagic keeps every offset fixed (pads with NULs)', () => {
    const elf = buildElf('license=GPL\0vermagic=1.0 SMP preempt ARMv7 p2v8\0');
    const before = parseElf(elf);

    const out = patchVermagic(elf, '1.0');
    const after = parseElf(out);

    expect(after.vermagic).toBe('1.0');
    expect(after.sections['.text'].off).toBe(before.sections['.text'].off);
    expect(after.shoff).toBe(before.shoff);
    expect(after.sections['.modinfo'].size).toBe(before.sections['.modinfo'].size);
    expect(out.length).toBe(elf.length);
    expect(out.slice(after.sections['.text'].off, after.sections['.text'].off + 8).toString())
      .toBe('ABCDEFGH');
  });

  test('preserves the target vermagic verbatim, including a trailing space', () => {
    const elf = buildElf('vermagic=1.0 SMP\0license=GPL\0');
    const out = patchVermagic(elf, '3.12.19-rt30 SMP mod_unload ARMv7 p2v8 ');
    expect(parseElf(out).vermagic).toBe('3.12.19-rt30 SMP mod_unload ARMv7 p2v8 ');
  });

  test('rejects non-ELF input, missing vermagic, and empty target', () => {
    expect(() => patchVermagic(Buffer.from('not an elf at all........'), '1.0'))
      .toThrow(/not an ELF/);
    expect(() => patchVermagic(buildElf('license=GPL\0author=x\0'), '1.0'))
      .toThrow(/vermagic= not found/);
    expect(() => patchVermagic(buildElf('vermagic=1.0\0'), ''))
      .toThrow(/empty/);
  });
});
