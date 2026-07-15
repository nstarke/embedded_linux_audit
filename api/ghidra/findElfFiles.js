// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const fsp = require('fs/promises');
const path = require('path');

// ELF identification: the 4-byte magic (0x7f 'E' 'L' 'F') plus enough of
// e_ident/e_type to classify the object. We treat every ELF as decompilable —
// executables (ET_EXEC), shared objects / PIE (ET_DYN) and relocatable objects
// including kernel modules (ET_REL) — because Ghidra can load all of them.
const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]); // \x7fELF
const HEADER_BYTES = 20; // magic(4) + rest of e_ident(12) + e_type(2) + slack

// e_type values (offset 16, honoring EI_DATA endianness at offset 5).
const ET_NAMES = {
  1: 'relocatable', // ET_REL — .o, .ko kernel modules
  2: 'executable', // ET_EXEC
  3: 'shared-object', // ET_DYN — .so, PIE executables
  4: 'core', // ET_CORE
};

// Default per-file size ceiling. analyzeHeadless auto-analysis balloons in
// memory and wall-clock on very large binaries; skip anything bigger unless the
// operator raises ELA_GHIDRA_MAX_FILE_BYTES. 0/unset here means "use default".
const DEFAULT_MAX_BYTES = 256 * 1024 * 1024; // 256 MiB

function classifyElf(header) {
  if (header.length < HEADER_BYTES || !header.subarray(0, 4).equals(ELF_MAGIC)) {
    return null;
  }
  // EI_DATA at offset 5: 1 = little-endian, 2 = big-endian.
  const eType = header[5] === 2
    ? header.readUInt16BE(16)
    : header.readUInt16LE(16);
  return ET_NAMES[eType] || 'unknown';
}

// Read just the leading header of a file and classify it. Returns the ELF type
// string, or null when the file is not an ELF / cannot be read.
async function classifyFile(absPath) {
  let fh;
  try {
    fh = await fsp.open(absPath, 'r');
  } catch {
    return null;
  }
  try {
    const buf = Buffer.alloc(HEADER_BYTES);
    const { bytesRead } = await fh.read(buf, 0, HEADER_BYTES, 0);
    return classifyElf(buf.subarray(0, bytesRead));
  } catch {
    return null;
  } finally {
    await fh.close().catch(() => {});
  }
}

/**
 * Recursively find every ELF file under `root`.
 *
 * Symlinks are never followed (lstat) — the uploaded tree already resolved
 * them at copy time, and following them here risks escaping `root` or looping.
 * Regular files above `maxBytes` are skipped (recorded in `skippedLarge`).
 *
 * @param {string} root  Absolute directory to scan (e.g. <data>/<mac>/fs).
 * @param {object} [opts]
 * @param {number} [opts.maxBytes]  Per-file size ceiling.
 * @param {object} [opts.fs]  Injected fs/promises-like API (tests).
 * @returns {Promise<{files: Array<{absPath:string, relPath:string, type:string, size:number}>, skippedLarge: number, errors: number}>}
 */
async function findElfFiles(root, { maxBytes = DEFAULT_MAX_BYTES, fs = fsp } = {}) {
  const files = [];
  let skippedLarge = 0;
  let errors = 0;
  const limit = maxBytes && maxBytes > 0 ? maxBytes : DEFAULT_MAX_BYTES;

  async function walk(dir) {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      errors += 1;
      return;
    }
    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        continue;
      }
      if (entry.isDirectory()) {
        await walk(abs);
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }
      let st;
      try {
        st = await fs.stat(abs);
      } catch {
        errors += 1;
        continue;
      }
      if (st.size < ELF_MAGIC.length) {
        continue;
      }
      if (st.size > limit) {
        skippedLarge += 1;
        continue;
      }
      const type = await classifyFileWith(fs, abs);
      if (type) {
        files.push({ absPath: abs, relPath: path.relative(root, abs), type, size: st.size });
      }
    }
  }

  await walk(root);
  files.sort((a, b) => a.relPath.localeCompare(b.relPath));
  return { files, skippedLarge, errors };
}

// classifyFile, but using an injected fs (for tests). Falls back to the real
// fs/promises open when the injected object lacks it.
async function classifyFileWith(fs, absPath) {
  const opener = fs.open ? fs : fsp;
  let fh;
  try {
    fh = await opener.open(absPath, 'r');
  } catch {
    return null;
  }
  try {
    const buf = Buffer.alloc(HEADER_BYTES);
    const { bytesRead } = await fh.read(buf, 0, HEADER_BYTES, 0);
    return classifyElf(buf.subarray(0, bytesRead));
  } catch {
    return null;
  } finally {
    await fh.close().catch(() => {});
  }
}

module.exports = {
  findElfFiles,
  classifyFile,
  classifyElf,
  ELF_MAGIC,
  DEFAULT_MAX_BYTES,
};
