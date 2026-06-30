#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { Worker } = require('bullmq');
const { QUEUE_NAME, getConnection } = require('../lib/queue');
const { runBuild } = require('./runBuild');

// Long-running worker: consumes per-user binary build jobs and runs the
// cross-compile. Concurrency 1 because builds share repoRoot/generated and
// third_party build directories, so they must be serialized.
const worker = new Worker(QUEUE_NAME, async (job) => {
  const { username, keyHash, outDir } = job.data || {};
  console.log(`[builder] build start  job=${job.id} user=${username} keyHash=${keyHash} -> ${outDir}`);
  const result = await runBuild(job.data);
  console.log(`[builder] build done   job=${job.id} user=${username} -> ${result.outDir}`);
  return result;
}, {
  connection: getConnection(),
  concurrency: 1,
});

worker.on('failed', (job, err) => {
  console.error(`[builder] build FAILED job=${job && job.id} user=${job && job.data && job.data.username}: ${err && err.message}`);
});

worker.on('error', (err) => {
  console.error(`[builder] worker error: ${err && err.message}`);
});

console.log(`[builder] worker listening on queue "${QUEUE_NAME}"`);

async function shutdown() {
  try {
    await worker.close();
  } finally {
    process.exit(0);
  }
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
