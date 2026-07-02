#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

/**
 * Remove a user created by add-user-key.js. The inverse cleanup:
 *   - deletes the user row (its api_keys cascade-delete; uploads are unlinked,
 *     i.e. uploads.user_id -> NULL, but the artifacts themselves are kept),
 *   - removes the per-user binary directories <assetsDir>/users/<keyHash>/,
 *   - removes that user's pending/finished build jobs from the queue.
 *
 * Usage:
 *   node tools/remove-user-key.js --username <username> [--assets-dir <dir>]
 *                                 [--keep-binaries] [--keep-queue]
 */

const path = require('path');
const fsp = require('fs/promises');

const repoRoot = path.resolve(__dirname, '..');
const { initializeDatabase, runMigrations, closeDatabase } = require(path.join(repoRoot, 'api/lib/db'));
const { getUserWithKeys, deleteUserByUsername } = require(path.join(repoRoot, 'api/lib/db/deviceRegistry'));
const { getAgentServiceConfig } = require(path.join(repoRoot, 'api/lib/config'));

// The queue (and its bullmq/redis deps) is only loaded when we actually touch
// it, so usage errors and --keep-queue don't require it.
function loadQueue() {
  return require(path.join(repoRoot, 'api/lib/queue'));
}

function getArg(flag) {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 ? process.argv[idx + 1] : null;
}

function hasFlag(flag) {
  return process.argv.includes(flag);
}

const username = getArg('--username');
const assetsDirArg = getArg('--assets-dir');
const keepBinaries = hasFlag('--keep-binaries');
const keepQueue = hasFlag('--keep-queue');

if (!username) {
  process.stderr.write('usage: remove-user-key.js --username <username> [--assets-dir <dir>] [--keep-binaries] [--keep-queue]\n');
  process.exit(1);
}

// Mirror tools/add-user-key.js so binary dirs are resolved identically.
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

// Remove this user's build jobs so a queued/pending build cannot recreate the
// binaries after we delete them. An already-running (active) job cannot be
// removed and is reported instead.
async function removeQueueJobs() {
  const { getBuildQueue, closeBuildQueue } = loadQueue();
  const queue = getBuildQueue();
  let removed = 0;
  let active = 0;
  try {
    const jobs = await queue.getJobs(['waiting', 'active', 'delayed', 'paused', 'failed', 'completed']);
    for (const job of jobs) {
      if (!job || !job.data || job.data.username !== username) {
        continue;
      }
      try {
        await job.remove();
        removed += 1;
      } catch {
        active += 1; // active/locked jobs cannot be removed
      }
    }
  } finally {
    await closeBuildQueue().catch(() => {});
  }
  return { removed, active };
}

async function main() {
  await initializeDatabase();
  await runMigrations();

  const user = await getUserWithKeys(username);
  if (!user) {
    await closeDatabase();
    process.stderr.write(`error: no such user: ${username}\n`);
    process.exit(1);
    return;
  }

  const keyHashes = user.keys.map((k) => k.keyHash);

  // 1. Drop pending build jobs first so nothing rebuilds during cleanup.
  let queueResult = { removed: 0, active: 0 };
  if (!keepQueue) {
    queueResult = await removeQueueJobs();
  }

  // 2. Delete the user (cascades api_keys; unlinks uploads).
  const deleted = await deleteUserByUsername(username);
  await closeDatabase();

  // 3. Remove the per-user binary directories.
  let removedDirs = 0;
  if (!keepBinaries) {
    const assetsDir = resolveAssetsDir();
    for (const keyHash of keyHashes) {
      const dir = path.join(assetsDir, 'users', keyHash);
      try {
        await fsp.rm(dir, { recursive: true, force: true });
        removedDirs += 1;
      } catch (err) {
        process.stderr.write(`warning: could not remove ${dir}: ${err.message}\n`);
      }
    }
  }

  process.stdout.write(`Removed user "${username}" (${deleted} row, ${user.keys.length} key(s)).\n`);
  if (!keepQueue) {
    process.stdout.write(`Build jobs removed: ${queueResult.removed}`);
    process.stdout.write(queueResult.active ? `; ${queueResult.active} active job(s) left running (re-run after they finish).\n` : '.\n');
  }
  if (!keepBinaries) {
    process.stdout.write(`Binary directories removed: ${removedDirs}.\n`);
  }
  process.stdout.write('Uploaded artifacts (if any) are retained but unlinked from the user.\n');
}

main().catch((err) => {
  process.stderr.write(`error: ${err.message}\n`);
  closeDatabase().catch(() => {}).finally(() => process.exit(1));
});
