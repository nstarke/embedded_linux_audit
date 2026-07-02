#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

/**
 * Report the state of per-user binary build jobs on the queue.
 *
 * Usage:
 *   node tools/build-status.js [--username <name>]
 *
 * Run inside the stack, e.g.:
 *   docker compose exec agent-api node /app/tools/build-status.js
 */

const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const { getBuildQueue, closeBuildQueue, QUEUE_NAME } = require(path.join(repoRoot, 'api/lib/queue'));

function getArg(flag) {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 ? process.argv[idx + 1] : null;
}

const usernameFilter = getArg('--username');

async function main() {
  const queue = getBuildQueue();

  const counts = await queue.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed');
  process.stdout.write(`queue: ${QUEUE_NAME}\n`);
  process.stdout.write(`counts: waiting=${counts.waiting || 0} active=${counts.active || 0} completed=${counts.completed || 0} failed=${counts.failed || 0} delayed=${counts.delayed || 0}\n\n`);

  const jobs = await queue.getJobs(['active', 'waiting', 'delayed', 'failed', 'completed'], 0, 50, false);
  const rows = jobs
    .filter((job) => job && job.data)
    .filter((job) => !usernameFilter || job.data.username === usernameFilter);

  if (rows.length === 0) {
    process.stdout.write(usernameFilter ? `no jobs for user "${usernameFilter}"\n` : 'no jobs\n');
  } else {
    for (const job of rows) {
      const state = await job.getState();
      const failed = job.failedReason ? `  failed: ${job.failedReason}` : '';
      process.stdout.write(`job ${job.id}  user=${job.data.username}  state=${state}  -> ${job.data.outDir}${failed}\n`);
    }
  }

  await closeBuildQueue();
}

main().catch((err) => {
  process.stderr.write(`error: ${err.message}\n`);
  closeBuildQueue().catch(() => {}).finally(() => process.exit(1));
});
