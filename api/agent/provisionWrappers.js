// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const path = require('path');
const fsp = require('fs/promises');
const { assembleWrapper } = require('./selfExtract');

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

module.exports = { listGenericBinaries, assembleUserWrappers, GENERIC_NAME_RE };
