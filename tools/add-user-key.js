#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

/**
 * Add a user and API key to the database, then enqueue a per-user agent binary
 * build (with that user's API token embedded) for the builder worker.
 *
 * Usage:
 *   node tools/add-user-key.js --username <username> [--label <label>] \
 *       [--key <plaintext-key>] [--assets-dir <dir>] [--skip-build]
 *
 * If --key is omitted a cryptographically random 32-byte hex key is generated.
 * The plaintext key is printed once and never stored — only its SHA-256 hash
 * is written to the database.
 *
 * The build itself runs asynchronously in the `builder` container: this tool
 * enqueues a job on the Redis-backed queue and returns immediately. The worker
 * cross-compiles every supported ISA with the token baked in (via
 * ELA_EMBEDDED_API_KEY) and writes them flat to
 * <assetsDir>/users/<keyHash>/ela-<isa>. Check progress with
 * tools/build-status.js. Pass --skip-build to only create the database records.
 */

const path = require('path');
const crypto = require('crypto');

// Resolve DB modules relative to the repo root so the script can be run
// from any working directory.
const repoRoot = path.resolve(__dirname, '..');
const { initializeDatabase, runMigrations, closeDatabase } = require(path.join(repoRoot, 'api/lib/db'));
const { createApiKey } = require(path.join(repoRoot, 'api/lib/db/deviceRegistry'));
const { getAgentServiceConfig } = require(path.join(repoRoot, 'api/lib/config'));
const { getBuildQueue, closeBuildQueue } = require(path.join(repoRoot, 'api/lib/queue'));

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

async function enqueueBuild(plaintextKey, keyHash) {
  const outDir = path.join(resolveAssetsDir(), 'users', keyHash);
  const queue = getBuildQueue();
  try {
    const job = await queue.add('build', {
      username,
      keyHash,
      embeddedKey: plaintextKey,
      outDir,
    }, {
      attempts: 1,
      removeOnComplete: 100,
      removeOnFail: 100,
    });
    return { outDir, jobId: job.id };
  } finally {
    await closeBuildQueue().catch(() => {});
  }
}

function printManualBuildFallback(plaintextKey, outDir) {
  process.stdout.write('\nThe build was NOT queued. Build it manually in the builder container:\n');
  process.stdout.write('  docker compose exec \\\n');
  process.stdout.write('    -e ELA_RELEASE_FLAT_OUTPUT=1 \\\n');
  process.stdout.write(`    -e ELA_EMBEDDED_API_KEY=${plaintextKey} \\\n`);
  process.stdout.write(`    -e DEST_RELEASE_DIR=${outDir} \\\n`);
  process.stdout.write('    builder sh /src/tests/compile_release_binaries_locally.sh\n');
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

  try {
    const { outDir, jobId } = await enqueueBuild(plaintextKey, keyHash);
    process.stdout.write(`\nBuild queued (job ${jobId}) -> ${outDir}\n`);
    process.stdout.write('The builder is compiling all ISAs in the background (this takes a while).\n');
    process.stdout.write('Check progress: docker compose exec agent-api node /app/tools/build-status.js\n');
  } catch (err) {
    process.stderr.write(`\nwarning: failed to queue the build: ${err.message}\n`);
    printManualBuildFallback(plaintextKey, path.join(resolveAssetsDir(), 'users', keyHash));
    process.exit(1);
  }
}

main().catch((err) => {
  process.stderr.write(`error: ${err.message}\n`);
  Promise.allSettled([closeDatabase(), closeBuildQueue()]).finally(() => process.exit(1));
});
