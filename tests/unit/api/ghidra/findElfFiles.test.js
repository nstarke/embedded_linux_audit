'use strict';

const os = require('os');
const path = require('path');
const fsp = require('fs/promises');

const { findElfFiles, classifyElf, ELF_MAGIC } = require('../../../../api/ghidra/findElfFiles');

// Minimal ELF-ish header: magic + EI_DATA byte + e_type at offset 16.
function elfHeader({ littleEndian = true, eType = 2 } = {}) {
  const buf = Buffer.alloc(20);
  ELF_MAGIC.copy(buf, 0);
  buf[5] = littleEndian ? 1 : 2;
  if (littleEndian) {
    buf.writeUInt16LE(eType, 16);
  } else {
    buf.writeUInt16BE(eType, 16);
  }
  return buf;
}

describe('classifyElf', () => {
  test('classifies little-endian executable', () => {
    expect(classifyElf(elfHeader({ eType: 2 }))).toBe('executable');
  });
  test('classifies shared object', () => {
    expect(classifyElf(elfHeader({ eType: 3 }))).toBe('shared-object');
  });
  test('classifies relocatable (kernel module)', () => {
    expect(classifyElf(elfHeader({ eType: 1 }))).toBe('relocatable');
  });
  test('honors big-endian EI_DATA for e_type', () => {
    expect(classifyElf(elfHeader({ littleEndian: false, eType: 2 }))).toBe('executable');
  });
  test('rejects non-ELF magic', () => {
    const buf = Buffer.alloc(20, 0x41);
    expect(classifyElf(buf)).toBeNull();
  });
  test('rejects a too-short buffer', () => {
    expect(classifyElf(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))).toBeNull();
  });
});

describe('findElfFiles', () => {
  let root;

  beforeEach(async () => {
    root = await fsp.mkdtemp(path.join(os.tmpdir(), 'ela-elf-test-'));
  });
  afterEach(async () => {
    await fsp.rm(root, { recursive: true, force: true });
  });

  async function write(rel, buf) {
    const abs = path.join(root, rel);
    await fsp.mkdir(path.dirname(abs), { recursive: true });
    await fsp.writeFile(abs, buf);
    return abs;
  }

  test('finds ELF files recursively and skips non-ELF and symlinks', async () => {
    await write('usr/bin/foo', elfHeader({ eType: 2 }));
    await write('lib/libbar.so', elfHeader({ eType: 3 }));
    await write('lib/modules/mod.ko', elfHeader({ eType: 1 }));
    await write('etc/hosts', Buffer.from('127.0.0.1 localhost\n'));
    await write('usr/share/pic.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 0]));
    // A symlink pointing at an ELF must not be reported.
    await fsp.symlink(path.join(root, 'usr/bin/foo'), path.join(root, 'usr/bin/foo-link'));

    const { files, skippedLarge, errors } = await findElfFiles(root);
    const rels = files.map((f) => f.relPath).sort();

    expect(rels).toEqual(['lib/libbar.so', 'lib/modules/mod.ko', 'usr/bin/foo']);
    expect(files.find((f) => f.relPath === 'lib/modules/mod.ko').type).toBe('relocatable');
    expect(skippedLarge).toBe(0);
    expect(errors).toBe(0);
  });

  test('skips files larger than maxBytes', async () => {
    await write('big', Buffer.concat([elfHeader(), Buffer.alloc(4096)]));
    const { files, skippedLarge } = await findElfFiles(root, { maxBytes: 100 });
    expect(files).toHaveLength(0);
    expect(skippedLarge).toBe(1);
  });

  test('returns empty for a non-existent root without throwing', async () => {
    const { files, errors } = await findElfFiles(path.join(root, 'nope'));
    expect(files).toHaveLength(0);
    expect(errors).toBe(1);
  });
});
