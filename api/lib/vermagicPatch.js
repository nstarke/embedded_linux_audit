// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

// Rewrite the `vermagic=` string in a compiled kernel module (.ko).
//
// A kernel module stores `vermagic=<string>\0` in its .modinfo section, and the
// loader compares it against the running kernel's. Some embedded/hardened
// kernels are built without CONFIG_MODULE_FORCE_LOAD, so `insmod --force` can't
// bypass that check (the load fails with ENOEXEC / "Exec format error") — the
// only way in is a module whose vermagic string matches exactly. When the ABI
// is otherwise compatible, patching this one string makes the module loadable.
//
// This is pure ELF byte-surgery (no objcopy): the build targets many arches and
// the host binutils can't necessarily parse a foreign .ko, so we parse the ELF
// ourselves. Supports ELF32/ELF64, little/big endian, and resizes .modinfo
// (fixing the section-header offsets) when the new vermagic differs in length.
//
// NOTE: this only changes the *string*, not the module ABI. It is correct when
// the kernel merely requires a matching vermagic; it does not make an
// ABI-incompatible module safe to load.

const ELF_MAGIC = 0x464c457f; // 0x7f 'E' 'L' 'F' little-endian
const VERMAGIC_KEY = 'vermagic=';

function reader(buf, le) {
  return {
    u16: (o) => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o)),
    u: (o, size) => {
      if (size === 4) return le ? buf.readUInt32LE(o) : buf.readUInt32BE(o);
      // ELF64 offsets/sizes; a .ko is far under 2^53, so Number is exact.
      return Number(le ? buf.readBigUInt64LE(o) : buf.readBigUInt64BE(o));
    },
    w: (val, o, size) => {
      if (size === 4) return le ? buf.writeUInt32LE(val, o) : buf.writeUInt32BE(val, o);
      return le ? buf.writeBigUInt64LE(BigInt(val), o) : buf.writeBigUInt64BE(BigInt(val), o);
    },
  };
}

// ELF header + section-header field layout, per class.
function layout(is64) {
  return is64
    ? {
      eShoff: 0x28, eShoffSize: 8, eShentsize: 0x3a, eShnum: 0x3c, eShstrndx: 0x3e,
      shName: 0, shOffset: 24, shSize: 32, offSize: 8,
    }
    : {
      eShoff: 0x20, eShoffSize: 4, eShentsize: 0x2e, eShnum: 0x30, eShstrndx: 0x32,
      shName: 0, shOffset: 16, shSize: 20, offSize: 4,
    };
}

/**
 * Return a new Buffer identical to `input` except that the module's `vermagic=`
 * entry is replaced with `vermagic=<targetVermagic>` (verbatim — the caller
 * passes the device's exact vermagic, trailing space and all).
 *
 * @param {Buffer} input          the .ko bytes
 * @param {string} targetVermagic the vermagic to bake in (exact)
 * @returns {Buffer}
 * @throws if the buffer is not an ELF, has no .modinfo, or no vermagic entry.
 */
function patchVermagic(input, targetVermagic) {
  if (!Buffer.isBuffer(input)) {
    throw new TypeError('patchVermagic expects a Buffer');
  }
  const vermagic = String(targetVermagic == null ? '' : targetVermagic);
  if (!vermagic) {
    throw new Error('target vermagic is empty');
  }
  if (input.length < 64 || input.readUInt32LE(0) !== ELF_MAGIC) {
    throw new Error('not an ELF file');
  }

  const buf = Buffer.from(input); // work on a copy
  const is64 = buf[4] === 2; // EI_CLASS: 1=32-bit, 2=64-bit
  const le = buf[5] === 1; // EI_DATA:  1=little, 2=big
  const L = layout(is64);
  const r = reader(buf, le);

  const eShoff = r.u(L.eShoff, L.eShoffSize);
  const eShentsize = r.u16(L.eShentsize);
  const eShnum = r.u16(L.eShnum);
  const eShstrndx = r.u16(L.eShstrndx);
  if (!eShoff || !eShnum) {
    throw new Error('ELF has no section headers');
  }
  const shdr = (i) => eShoff + (i * eShentsize);

  // Resolve section names via the section-header string table.
  const shstrOff = r.u(shdr(eShstrndx) + L.shOffset, L.offSize);
  const nameAt = (i) => {
    const at = shstrOff + r.u(shdr(i) + L.shName, 4);
    let e = at;
    while (e < buf.length && buf[e] !== 0) e += 1;
    return buf.toString('ascii', at, e);
  };

  let miIdx = -1;
  for (let i = 0; i < eShnum; i += 1) {
    if (nameAt(i) === '.modinfo') { miIdx = i; break; }
  }
  if (miIdx < 0) {
    throw new Error('.modinfo section not found');
  }
  const miOffset = r.u(shdr(miIdx) + L.shOffset, L.offSize);
  const miSize = r.u(shdr(miIdx) + L.shSize, L.offSize);
  const modinfo = buf.slice(miOffset, miOffset + miSize);

  // .modinfo is a run of NUL-terminated `key=value` strings; find the one that
  // starts (at a NUL boundary) with "vermagic=".
  const key = Buffer.from(VERMAGIC_KEY, 'ascii');
  let start = -1;
  for (let idx = modinfo.indexOf(key); idx !== -1; idx = modinfo.indexOf(key, idx + 1)) {
    if (idx === 0 || modinfo[idx - 1] === 0) { start = idx; break; }
  }
  if (start < 0) {
    throw new Error('vermagic= not found in .modinfo');
  }
  let end = start;
  while (end < modinfo.length && modinfo[end] !== 0) end += 1;

  const newEntry = Buffer.from(VERMAGIC_KEY + vermagic, 'ascii');
  let newModinfo = Buffer.concat([modinfo.slice(0, start), newEntry, modinfo.slice(end)]);

  let delta = newModinfo.length - miSize;
  if (delta < 0) {
    // Shorter: pad with NULs back to the original size so nothing moves (the
    // loader scans to the first NUL, so trailing NULs are ignored).
    newModinfo = Buffer.concat([newModinfo, Buffer.alloc(-delta)]);
    delta = 0;
  } else if (delta > 0) {
    // Longer: round the growth up to 8 bytes so every following section keeps
    // its file-offset alignment after the shift.
    const pad = (8 - (delta % 8)) % 8;
    if (pad) {
      newModinfo = Buffer.concat([newModinfo, Buffer.alloc(pad)]);
      delta += pad;
    }
  }

  const out = Buffer.concat([
    buf.slice(0, miOffset),
    newModinfo,
    buf.slice(miOffset + miSize),
  ]);

  if (delta !== 0) {
    // The section-header table (and any section) that sits after .modinfo moved
    // by `delta`; fix e_shoff and each shifted sh_offset, plus .modinfo's size.
    const outShoff = eShoff > miOffset ? eShoff + delta : eShoff;
    const rw = reader(out, le);
    if (eShoff > miOffset) {
      rw.w(outShoff, L.eShoff, L.eShoffSize);
    }
    const outShdr = (i) => outShoff + (i * eShentsize);
    for (let i = 0; i < eShnum; i += 1) {
      const origOff = r.u(shdr(i) + L.shOffset, L.offSize); // read from original table
      if (origOff > miOffset) {
        rw.w(origOff + delta, outShdr(i) + L.shOffset, L.offSize);
      }
    }
    rw.w(newModinfo.length, outShdr(miIdx) + L.shSize, L.offSize);
  }

  return out;
}

module.exports = { patchVermagic, VERMAGIC_KEY };
