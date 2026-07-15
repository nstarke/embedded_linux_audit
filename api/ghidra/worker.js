#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { Worker } = require('bullmq');
const {
  GHIDRA_ANALYSIS_QUEUE_NAME,
  getGhidraAnalysisWorkerOptions,
} = require('../lib/queue');
const { runGhidraAnalysis } = require('./runGhidraAnalysis');

// Lazily resolve DB helpers so requiring this module in tests does not pull in
// sequelize/postgres.
function ghidraJobs() {
  return require('../lib/db/ghidraJobs');
}

/**
 * Start the ghidra-analysis worker. Each job payload is
 * `{ jobId, deviceId, mac }` (the ghidra_analysis_jobs row the client API
 * created). The heavy lifting — remote-copy of the device rootfs and the
 * recursive analyzeHeadless decompile — happens in runGhidraAnalysis, which
 * writes the status transitions itself; the worker only frames the run and
 * records a terminal failure.
 *
 * @param {{run?:Function, db?:object}} [deps]  Test injection.
 * @returns {Worker}
 */
function startGhidraAnalysisWorker(deps = {}) {
  const runImpl = deps.run || runGhidraAnalysis;
  const db = deps.db || null;
  const dbApi = () => db || ghidraJobs();

  const options = getGhidraAnalysisWorkerOptions();
  console.log(
    `[ghidra] worker options: concurrency=${options.concurrency} `
    + `lockDuration=${options.lockDuration}ms`,
  );

  const worker = new Worker(GHIDRA_ANALYSIS_QUEUE_NAME, async (job) => {
    const { jobId, deviceId, mac } = job.data || {};
    console.log(`[ghidra] job start id=${job.id} jobId=${jobId} device=${deviceId} mac=${mac}`);
    try {
      const result = await runImpl({ jobId, deviceId, mac }, { log: (m) => console.log(m) });
      console.log(`[ghidra] job done id=${job.id} jobId=${jobId} `
        + `found=${result.filesFound} analyzed=${result.filesAnalyzed} -> ${result.outputRoot}`);
      return result;
    } catch (err) {
      if (jobId) {
        await dbApi().markFailed(jobId, err && err.message).catch((updateErr) => {
          console.error(`[ghidra] failed to mark job ${jobId} failed: ${updateErr && updateErr.message}`);
        });
      }
      throw err;
    }
  }, options);

  worker.on('failed', (job, err) => {
    console.error(`[ghidra] job FAILED id=${job && job.id} `
      + `jobId=${job && job.data && job.data.jobId}: ${err && err.message}`);
  });

  worker.on('error', (err) => {
    console.error(`[ghidra] worker error: ${err && err.message}`);
  });

  console.log(`[ghidra] worker listening on queue "${GHIDRA_ANALYSIS_QUEUE_NAME}"`);
  return worker;
}

module.exports = { startGhidraAnalysisWorker };

// As the container entrypoint, start the worker directly. The DB connection is
// created lazily on the first status write (the module_build/ghidra tables are
// migrated by the API services at their startup), mirroring the builder worker;
// this avoids racing several services on Umzug migrations.
if (require.main === module) {
  const worker = startGhidraAnalysisWorker();

  async function shutdown() {
    try {
      await worker.close();
    } finally {
      process.exit(0);
    }
  }
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
