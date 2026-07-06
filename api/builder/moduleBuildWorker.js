// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { Worker } = require('bullmq');
const { MODULE_BUILD_QUEUE_NAME, getModuleBuildWorkerOptions } = require('../lib/queue');
const { runModuleBuild } = require('./runModuleBuild');

// Lazily resolve the DB helpers so importing this module in tests does not
// pull in sequelize/postgres.
function moduleBuilds() {
  return require('../lib/db/moduleBuilds');
}

/**
 * Start the kernel-module build worker. Each job's payload is the argument
 * shape of runModuleBuild plus `requestId` (the module_build_requests row this
 * job realizes). Status transitions are written around the build so operators
 * can poll GET /module-builds/:id while the compile runs.
 *
 * DB updates are best-effort: a status-write failure must not kill the build
 * (the job result still lands in BullMQ), so they are logged and swallowed.
 *
 * @param {{runBuild?:Function, db?:object}} [deps]  Test injection.
 * @returns {Worker}
 */
function startModuleBuildWorker(deps = {}) {
  const runBuildImpl = deps.runBuild || runModuleBuild;
  const db = deps.db || null;
  const dbApi = () => db || moduleBuilds();

  const options = getModuleBuildWorkerOptions();
  console.log(
    `[builder] module-build worker options: concurrency=${options.concurrency} `
    + `lockDuration=${options.lockDuration}ms`,
  );

  const worker = new Worker(MODULE_BUILD_QUEUE_NAME, async (job) => {
    const { requestId } = job.data || {};
    console.log(`[builder] module build start job=${job.id} request=${requestId} `
      + `kernel=${job.data && job.data.kernelRelease} isa=${job.data && job.data.isa}`);

    if (requestId) {
      await dbApi().markBuildStarted(requestId).catch((err) => {
        console.error(`[builder] failed to mark request ${requestId} building: ${err && err.message}`);
      });
    }

    try {
      const result = await runBuildImpl(job.data);
      if (requestId) {
        await dbApi().markBuildSucceeded(requestId, {
          builtVermagic: result.builtVermagic,
          vermagicResult: result.vermagicResult,
          source: result.source,
          artifactPath: result.koPath,
        }).catch((err) => {
          console.error(`[builder] failed to mark request ${requestId} succeeded: ${err && err.message}`);
        });
      }
      console.log(`[builder] module build done  job=${job.id} request=${requestId} `
        + `vermagic=${result.builtVermagic} (${result.vermagicResult})`);
      return result;
    } catch (err) {
      if (requestId) {
        await dbApi().markBuildFailed(requestId, err && err.message).catch((updateErr) => {
          console.error(`[builder] failed to mark request ${requestId} failed: ${updateErr && updateErr.message}`);
        });
      }
      throw err;
    }
  }, options);

  worker.on('failed', (job, err) => {
    console.error(`[builder] module build FAILED job=${job && job.id} `
      + `request=${job && job.data && job.data.requestId}: ${err && err.message}`);
  });

  worker.on('error', (err) => {
    console.error(`[builder] module-build worker error: ${err && err.message}`);
  });

  console.log(`[builder] module-build worker listening on queue "${MODULE_BUILD_QUEUE_NAME}"`);
  return worker;
}

module.exports = { startModuleBuildWorker };
