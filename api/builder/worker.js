#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const fsp = require('fs/promises');
const { Worker } = require('bullmq');
const { QUEUE_NAME, getWorkerOptions, getBuildQueue, closeBuildQueue } = require('../lib/queue');
const { runBuild } = require('./runBuild');
const { startModuleBuildWorker } = require('./moduleBuildWorker');
const { resolveAssetsDir, genericDir } = require('../lib/agentAssets');

// The one-time generic build: cross-compile every ISA once, with no token/URL
// embedded, into <assetsDir>/generic. Per-user launchers are assembled from
// these by tools/add-user-key.js (no compilation per user).
const GENERIC_DIR = genericDir(resolveAssetsDir());

async function hasGenericBinaries() {
  const entries = await fsp.readdir(GENERIC_DIR, { withFileTypes: true }).catch(() => []);
  return entries.some((e) => e.isFile() && e.name.startsWith('ela-'));
}

// On startup, enqueue the generic build if it has not been produced yet. The
// worker below then consumes it. Idempotent across restarts (skipped once the
// binaries exist).
async function bootstrapGenericBuild() {
  try {
    if (await hasGenericBinaries()) {
      console.log(`[builder] generic binaries present in ${GENERIC_DIR}; skipping bootstrap build`);
      return;
    }
    await getBuildQueue().add('generic', { outDir: GENERIC_DIR }, {
      jobId: 'generic-bootstrap', // dedupe: at most one pending/active bootstrap job
      attempts: 1,
      // Remove the record on completion so a future rebuild (e.g. the generic
      // dir was wiped) is not blocked by the fixed jobId still existing.
      removeOnComplete: true,
      removeOnFail: true,
    });
    console.log(`[builder] enqueued one-time generic build -> ${GENERIC_DIR}`);
  } catch (err) {
    console.error(`[builder] failed to enqueue generic build: ${err && err.message}`);
  } finally {
    await closeBuildQueue().catch(() => {});
  }
}

// Long-running worker: consumes per-user binary build jobs and runs the
// cross-compile. Concurrency defaults to 1 because builds share
// repoRoot/generated and third_party build directories, so they must be
// serialized. lockDuration/maxStalledCount are raised well above BullMQ's
// defaults so a slow-but-healthy build is not declared stalled (see
// getWorkerOptions); all are env-overridable.
const workerOptions = getWorkerOptions();
console.log(
  `[builder] worker options: concurrency=${workerOptions.concurrency} `
  + `lockDuration=${workerOptions.lockDuration}ms `
  + `stalledInterval=${workerOptions.stalledInterval}ms `
  + `maxStalledCount=${workerOptions.maxStalledCount}`,
);
const worker = new Worker(QUEUE_NAME, async (job) => {
  const { username, keyHash, outDir } = job.data || {};
  console.log(`[builder] build start  job=${job.id} user=${username} keyHash=${keyHash} -> ${outDir}`);
  const result = await runBuild(job.data);
  console.log(`[builder] build done   job=${job.id} user=${username} -> ${result.outDir}`);
  return result;
}, workerOptions);

worker.on('failed', (job, err) => {
  console.error(`[builder] build FAILED job=${job && job.id} user=${job && job.data && job.data.username}: ${err && err.message}`);
});

worker.on('error', (err) => {
  console.error(`[builder] worker error: ${err && err.message}`);
});

console.log(`[builder] worker listening on queue "${QUEUE_NAME}"`);

// Kernel-module builds run on their own queue with their own concurrency so a
// slow modules_prepare never blocks binary/launcher builds.
const moduleBuildWorker = startModuleBuildWorker();

// Kick off the one-time generic build if needed (fire-and-forget; the worker
// above consumes the enqueued job).
bootstrapGenericBuild();

async function shutdown() {
  try {
    await worker.close();
    await moduleBuildWorker.close();
  } finally {
    process.exit(0);
  }
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
