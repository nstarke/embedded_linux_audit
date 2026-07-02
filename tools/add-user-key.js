#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

/**
 * Add a user and API key to the database, then assemble that user's agent
 * launchers from the one-time generic binaries.
 *
 * Usage:
 *   node tools/add-user-key.js --username <username> [--label <label>] \
 *       [--key <plaintext-key>] [--server-url <wss://host>] \
 *       [--assets-dir <dir>] [--insecure] [--skip-build]
 *
 * If --key is omitted a cryptographically random 32-byte hex agent key is
 * generated. Only SHA-256 hashes are stored. The **agent** token is an
 * agent-only credential — it is baked into the launchers and is NOT printed;
 * only the **client** token (the operator's credential for the client API) is
 * shown, once.
 *
 * No compilation happens here. The agent is cross-compiled ONCE into generic
 * (unembedded) binaries at <assetsDir>/generic/ela-<isa> (see the builder
 * worker). This tool wraps each generic binary in a self-extracting shell
 * launcher that sets the user's token (ELA_API_KEY) and the terminal-API URL at
 * runtime, writing them to <assetsDir>/users/<keyHash>/ela-<isa>. That is pure
 * file I/O and completes instantly. Pass --skip-build to only create the DB
 * records (no launchers written).
 */

const path = require('path');
const crypto = require('crypto');

// Resolve DB modules relative to the repo root so the script can be run
// from any working directory.
const repoRoot = path.resolve(__dirname, '..');
const { initializeDatabase, runMigrations, closeDatabase } = require(path.join(repoRoot, 'api/lib/db'));
const { createApiKey } = require(path.join(repoRoot, 'api/lib/db/deviceRegistry'));
const { resolveAssetsDir: resolveAssets, genericDir, userDir } = require(path.join(repoRoot, 'api/lib/agentAssets'));
const { assembleUserWrappers } = require(path.join(repoRoot, 'api/agent/provisionWrappers'));

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
// Base WS URL of the terminal API to seed into the launcher so a bare run
// auto-connects. Falls back to ELA_SERVER_URL; empty means "no phone-home".
const serverUrl = getArg('--server-url') || process.env.ELA_SERVER_URL || '';
const insecure = hasFlag('--insecure');
const skipBuild = hasFlag('--skip-build');

if (!username) {
  process.stderr.write('usage: add-user-key.js --username <username> [--label <label>] [--key <plaintext-key>] [--server-url <wss://host>] [--assets-dir <dir>] [--insecure] [--skip-build]\n');
  process.exit(1);
}

function resolveAssetsDir() {
  return resolveAssets({ assetsDirArg, repoRoot });
}

// Wrap each generic binary in a per-user self-extracting launcher. Instant
// (pure file I/O) — no compilation. Requires the one-time generic build to have
// produced <assetsDir>/generic/ela-<isa> first.
async function assembleLaunchers(plaintextKey, keyHash) {
  const assetsDir = resolveAssetsDir();
  const dest = userDir(assetsDir, keyHash);
  const { written } = await assembleUserWrappers({
    genericDir: genericDir(assetsDir),
    userDir: dest,
    token: plaintextKey,
    serverUrl,
    insecure,
  });
  return { outDir: dest, isas: written.map((w) => w.isa) };
}

function printGenericBuildHint(assetsDir) {
  process.stdout.write('\nNo generic binaries found — the one-time build has not run yet.\n');
  process.stdout.write(`Expected them at ${genericDir(assetsDir)}/ela-<isa>.\n`);
  process.stdout.write('The builder produces them automatically on first start; wait for it to\n');
  process.stdout.write('finish (docker compose logs -f builder), then re-run this command.\n');
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
  process.stdout.write(`client key: ${clientKey}\n`);
  process.stdout.write('\nStore the client key securely — it will not be shown again. It is your\n');
  process.stdout.write('operator credential for the client API. The agent token is an agent-only\n');
  process.stdout.write('credential baked into the launchers below, so it is not printed.\n');

  if (skipBuild) {
    process.stdout.write('\nSkipping launcher assembly (--skip-build).\n');
    return;
  }

  try {
    const { outDir, isas } = await assembleLaunchers(plaintextKey, keyHash);
    process.stdout.write(`\nLaunchers written (${isas.length} ISAs) -> ${outDir}\n`);
    process.stdout.write(`Distribute the launcher for the target's ISA (e.g. ela-${isas[0] || 'x86_64'}) from that\n`);
    process.stdout.write('directory, `chmod +x`, and run it on the target — it sets the agent token and\n');
    process.stdout.write('(if a server URL was configured) phones home to the terminal API on a bare run.\n');
  } catch (err) {
    process.stderr.write(`\nwarning: failed to assemble launchers: ${err.message}\n`);
    printGenericBuildHint(resolveAssetsDir());
    process.exit(1);
  }
}

main().catch((err) => {
  process.stderr.write(`error: ${err.message}\n`);
  closeDatabase().catch(() => {}).finally(() => process.exit(1));
});
