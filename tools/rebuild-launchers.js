#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

/**
 * Rebuild the self-extracting launchers for already-provisioned users from the
 * current generic binaries and server URL — without changing any tokens or
 * download URLs. Use this after configuring/changing ELA_SERVER_URL, or after a
 * fresh generic build, to apply the new URL to existing users.
 *
 * Each user's token is recovered from one of their existing launchers (the DB
 * stores only the hash), so this needs no database — just filesystem access to
 * the shared assets volume.
 *
 * Usage:
 *   node tools/rebuild-launchers.js [--server-url <wss://host>] [--assets-dir <dir>]
 *       [--keyhash <sha256>] [--insecure | --no-insecure]
 *
 * --server-url   URL to bake in; defaults to ELA_SERVER_URL. Empty ⇒ launchers
 *                will NOT phone home (a bare run prints the agent help).
 * --keyhash      Rebuild only this one user's directory (users/<keyhash>/).
 * --insecure     Force TLS verification off in the rebuilt launchers.
 * --no-insecure  Force it on. Default: keep each launcher's current setting.
 */

const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const { resolveAssetsDir, genericDir, USERS_SUBDIR } = require(path.join(repoRoot, 'api/lib/agentAssets'));
const { rebuildAllLaunchers } = require(path.join(repoRoot, 'api/agent/provisionWrappers'));

function getArg(flag) {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 ? process.argv[idx + 1] : null;
}

function hasFlag(flag) {
  return process.argv.includes(flag);
}

const assetsDirArg = getArg('--assets-dir');
const serverUrl = getArg('--server-url') || process.env.ELA_SERVER_URL || '';
const onlyKeyHash = getArg('--keyhash');
const insecureOverride = hasFlag('--insecure') ? true : (hasFlag('--no-insecure') ? false : null);

async function main() {
  const assetsDir = resolveAssetsDir({ assetsDirArg, repoRoot });
  const usersDir = path.join(assetsDir, USERS_SUBDIR);

  if (!serverUrl) {
    process.stdout.write('warning: no --server-url / ELA_SERVER_URL set; rebuilt launchers will NOT phone home\n');
  }

  const { rebuilt, skipped } = await rebuildAllLaunchers({
    genericDir: genericDir(assetsDir),
    usersDir,
    serverUrl,
    insecureOverride,
    onlyKeyHash,
  });

  for (const r of rebuilt) {
    process.stdout.write(`rebuilt ${r.keyHash} (${r.isas.length} ISAs)\n`);
  }
  for (const s of skipped) {
    process.stderr.write(`skipped ${s.keyHash}: ${s.reason}\n`);
  }

  process.stdout.write(`\nDone: ${rebuilt.length} user(s) rebuilt, ${skipped.length} skipped.\n`);
  if (serverUrl) {
    process.stdout.write(`Server URL baked in: ${serverUrl}\n`);
  }
}

main().catch((err) => {
  process.stderr.write(`error: ${err.message}\n`);
  process.exit(1);
});
