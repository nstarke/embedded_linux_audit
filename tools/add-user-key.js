#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

/**
 * Add a user and API key to the database, then build per-user agent binaries
 * with that user's API token embedded.
 *
 * Usage:
 *   node tools/add-user-key.js --username <username> [--label <label>] \
 *       [--key <plaintext-key>] [--assets-dir <dir>] [--skip-build]
 *
 * If --key is omitted a cryptographically random 32-byte hex key is generated.
 * The plaintext key is printed once and never stored — only its SHA-256 hash
 * is written to the database.
 *
 * After the key is created the agent binaries are cross-compiled for every
 * supported ISA with the token baked in (via ELA_EMBEDDED_API_KEY) and written
 * flat to <assetsDir>/users/<keyHash>/ela-<isa>, where the agent helper server
 * serves them for requests bearing that token.  Pass --skip-build to only
 * create the database record (e.g. when the binaries are built separately).
 */

const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

// Resolve DB modules relative to the repo root so the script can be run
// from any working directory.
const repoRoot = path.resolve(__dirname, '..');
const { initializeDatabase, runMigrations, closeDatabase } = require(path.join(repoRoot, 'api/lib/db'));
const { createApiKey } = require(path.join(repoRoot, 'api/lib/db/deviceRegistry'));
const { getAgentServiceConfig } = require(path.join(repoRoot, 'api/lib/config'));

function getArg(flag) {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 ? process.argv[idx + 1] : null;
}

function hasFlag(flag) {
  return process.argv.includes(flag);
}

const username = getArg('--username');
const label = getArg('--label') || null;
const providedKey = getArg('--key');
const assetsDirArg = getArg('--assets-dir');
const skipBuild = hasFlag('--skip-build');

if (!username) {
  process.stderr.write('usage: add-user-key.js --username <username> [--label <label>] [--key <plaintext-key>] [--assets-dir <dir>] [--skip-build]\n');
  process.exit(1);
}

/**
 * Resolve the assets directory the agent helper server serves from, mirroring
 * api/agent/server.js: ELA_AGENT_ASSETS_DIR when set, otherwise
 * <dataRoot>/release_binaries.
 */
function resolveAssetsDir() {
  if (assetsDirArg) {
    return path.isAbsolute(assetsDirArg) ? assetsDirArg : path.resolve(repoRoot, assetsDirArg);
  }
  const svc = getAgentServiceConfig();
  if (svc.assetsDir) {
    return path.isAbsolute(svc.assetsDir) ? svc.assetsDir : path.resolve(repoRoot, svc.assetsDir);
  }
  const dataRoot = path.isAbsolute(svc.dataDir) ? svc.dataDir : path.resolve(repoRoot, svc.dataDir);
  return path.join(dataRoot, 'release_binaries');
}

function buildUserBinaries(plaintextKey, keyHash) {
  const outDir = path.join(resolveAssetsDir(), 'users', keyHash);
  const script = path.join(repoRoot, 'tests/compile_release_binaries_locally.sh');

  process.stdout.write(`\nBuilding per-user agent binaries into ${outDir}\n`);
  const result = spawnSync(script, [], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: {
      ...process.env,
      DEST_RELEASE_DIR: outDir,
      ELA_EMBEDDED_API_KEY: plaintextKey,
      ELA_RELEASE_FLAT_OUTPUT: '1',
    },
  });

  if (result.error) {
    throw new Error(`failed to launch build script: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`build script exited with status ${result.status}`);
  }
  return outDir;
}

async function main() {
  // Agent token — embedded into the user's agent binaries.
  const plaintextKey = providedKey || crypto.randomBytes(32).toString('hex');
  const keyHash = crypto.createHash('sha256').update(plaintextKey, 'utf8').digest('hex');

  // Client token — used by the client API to read back this user's artifacts.
  const clientKey = crypto.randomBytes(32).toString('hex');
  const clientHash = crypto.createHash('sha256').update(clientKey, 'utf8').digest('hex');

  await initializeDatabase();
  await runMigrations();

  const { created } = await createApiKey(username, keyHash, label, 'agent');
  const clientLabel = label ? `${label} (client)` : 'client';
  const { created: clientCreated } = await createApiKey(username, clientHash, clientLabel, 'client');

  await closeDatabase();

  if (!created) {
    process.stderr.write('error: an agent key with the same value already exists\n');
    process.exit(1);
  }
  if (!clientCreated) {
    process.stderr.write('error: a client key with the same value already exists\n');
    process.exit(1);
  }

  process.stdout.write(`username:   ${username}\n`);
  if (label) process.stdout.write(`label:      ${label}\n`);
  process.stdout.write(`agent key:  ${plaintextKey}\n`);
  process.stdout.write(`client key: ${clientKey}\n`);
  process.stdout.write('\nStore these keys securely — they will not be shown again.\n');
  process.stdout.write('The agent key is embedded into the agent binaries; the client key is for the client API.\n');

  if (skipBuild) {
    process.stdout.write('\nSkipping per-user binary build (--skip-build).\n');
    return;
  }

  const outDir = buildUserBinaries(plaintextKey, keyHash);
  process.stdout.write(`\nPer-user agent binaries written to ${outDir}\n`);
}

main().catch((err) => {
  process.stderr.write(`error: ${err.message}\n`);
  closeDatabase().catch(() => {}).finally(() => process.exit(1));
});
