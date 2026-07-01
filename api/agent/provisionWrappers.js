// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const path = require('path');
const fsp = require('fs/promises');
const { assembleWrapper, parseLauncherHeader, PAYLOAD_MARKER } = require('./selfExtract');

// Match the generic binaries produced by the release build: `ela-<isa>`.
const GENERIC_NAME_RE = /^ela-(.+)$/;

/**
 * List the generic (unembedded) binaries available for wrapping.
 * @returns {Promise<Array<{isa:string, fileName:string}>>} sorted by isa; [] if none.
 */
async function listGenericBinaries(genericDir, fs = fsp) {
  const entries = await fs.readdir(genericDir, { withFileTypes: true }).catch(() => []);
  return entries
    .filter((e) => e.isFile())
    .map((e) => {
      const m = e.name.match(GENERIC_NAME_RE);
      return m ? { isa: m[1], fileName: e.name } : null;
    })
    .filter(Boolean)
    .sort((a, b) => a.isa.localeCompare(b.isa));
}

/**
 * Assemble a per-user self-extracting launcher for every generic binary and
 * write them to the user's directory as `ela-<isa>`. This is pure file I/O (no
 * compilation), so it completes in milliseconds.
 *
 * @param {object} opts
 * @param {string} opts.genericDir  Directory holding `ela-<isa>` generic binaries.
 * @param {string} opts.userDir     Destination `<assetsDir>/users/<keyHash>`.
 * @param {string} opts.token       Agent bearer token to embed (as ELA_API_KEY).
 * @param {string} [opts.serverUrl] Terminal-API URL to seed for phone-home.
 * @param {boolean} [opts.insecure]
 * @param {object} [opts.fs]        fs/promises-like injection point (tests).
 * @returns {Promise<{written: Array<{isa:string, path:string}>}>}
 * @throws if no generic binaries exist (the one-time generic build must run first).
 */
async function assembleUserWrappers({ genericDir, userDir, token, serverUrl = '', insecure = false, fs = fsp }) {
  if (!token) throw new Error('assembleUserWrappers: token is required');

  const generics = await listGenericBinaries(genericDir, fs);
  if (generics.length === 0) {
    throw new Error(`no generic binaries in ${genericDir}; run the one-time generic build first`);
  }

  await fs.mkdir(userDir, { recursive: true });

  const written = [];
  for (const { isa, fileName } of generics) {
    const binary = await fs.readFile(path.join(genericDir, fileName));
    const wrapper = assembleWrapper(binary, { token, serverUrl, insecure, isa });
    const dest = path.join(userDir, `ela-${isa}`);
    await fs.writeFile(dest, wrapper, { mode: 0o755 });
    written.push({ isa, path: dest });
  }
  return { written };
}

// Read the token (and insecure flag) baked into an existing launcher by parsing
// its header — the only place a provisioned user's plaintext token still lives
// (the DB stores only its hash). Returns null if the file has no parseable
// header.
async function readLauncherMetadata(launcherPath, fs = fsp) {
  const buf = await fs.readFile(launcherPath);
  const marker = Buffer.from(`\n${PAYLOAD_MARKER}\n`);
  const idx = buf.indexOf(marker);
  const headerText = (idx === -1 ? buf : buf.subarray(0, idx)).toString('utf8');
  return parseLauncherHeader(headerText);
}

/**
 * Rebuild the launchers for already-provisioned users from the current generic
 * binaries and (typically) a newly-configured server URL. Each user's token is
 * recovered from one of their existing launchers, so tokens and download URLs
 * are preserved — only the wrapped binary and the baked-in URL/insecure change.
 *
 * @param {object} opts
 * @param {string} opts.genericDir
 * @param {string} opts.usersDir            `<assetsDir>/users`.
 * @param {string} [opts.serverUrl]         URL to bake in (empty ⇒ no phone-home).
 * @param {boolean|null} [opts.insecureOverride]  Force insecure on/off; null ⇒ keep each launcher's current value.
 * @param {string|null} [opts.onlyKeyHash]  Limit to a single user directory.
 * @param {object} [opts.fs]
 * @returns {Promise<{rebuilt: Array<{keyHash:string, isas:string[]}>, skipped: Array<{keyHash:string, reason:string}>}>}
 * @throws if no generic binaries exist.
 */
async function rebuildAllLaunchers({
  genericDir,
  usersDir,
  serverUrl = '',
  insecureOverride = null,
  onlyKeyHash = null,
  fs = fsp,
}) {
  const generics = await listGenericBinaries(genericDir, fs);
  if (generics.length === 0) {
    throw new Error(`no generic binaries in ${genericDir}; run the one-time generic build first`);
  }

  const dirents = await fs.readdir(usersDir, { withFileTypes: true }).catch(() => []);
  const keyHashes = dirents
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .filter((name) => !onlyKeyHash || name === onlyKeyHash)
    .sort();

  const rebuilt = [];
  const skipped = [];
  for (const keyHash of keyHashes) {
    const dir = path.join(usersDir, keyHash);
    const existing = (await fs.readdir(dir, { withFileTypes: true }).catch(() => []))
      .filter((e) => e.isFile() && e.name.startsWith('ela-'));
    if (existing.length === 0) {
      skipped.push({ keyHash, reason: 'no existing launcher to read the token from' });
      continue;
    }

    let meta = null;
    try {
      meta = await readLauncherMetadata(path.join(dir, existing[0].name), fs);
    } catch {
      meta = null;
    }
    if (!meta || !meta.token) {
      skipped.push({ keyHash, reason: 'could not recover the token from the existing launcher' });
      continue;
    }

    const insecure = insecureOverride != null ? insecureOverride : meta.insecure;
    const { written } = await assembleUserWrappers({
      genericDir, userDir: dir, token: meta.token, serverUrl, insecure, fs,
    });
    rebuilt.push({ keyHash, isas: written.map((w) => w.isa) });
  }

  return { rebuilt, skipped };
}

module.exports = {
  listGenericBinaries,
  assembleUserWrappers,
  readLauncherMetadata,
  rebuildAllLaunchers,
  GENERIC_NAME_RE,
};
