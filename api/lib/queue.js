'use strict';

const { Queue } = require('bullmq');

// Shared BullMQ definition used by the producer (tools/add-user-key.js) and the
// builder worker (api/builder/worker.js). Per-user binary builds are enqueued
// here so the API never has to compile anything itself.
const QUEUE_NAME = process.env.ELA_BUILD_QUEUE_NAME || 'ela-binary-builds';

function getConnection() {
  return {
    host: process.env.REDIS_HOST || 'redis',
    port: Number.parseInt(process.env.REDIS_PORT || '6379', 10),
  };
}

function intFromEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

/**
 * Build the BullMQ Worker options for the binary builder.
 *
 * A per-user cross-compile runs for many minutes, so the defaults here are far
 * larger than BullMQ's (lockDuration 30s, maxStalledCount 1) to keep a slow but
 * healthy build from being declared "stalled" and failed. The worker renews the
 * job lock every `lockDuration / 2` while the build child runs, so lockDuration
 * is effectively the ceiling on how long the worker may go without renewing
 * (e.g. a brief event-loop or Redis hiccup) before the job is considered lost.
 * All three are overridable by env var.
 */
function getWorkerOptions() {
  return {
    connection: getConnection(),
    concurrency: intFromEnv('ELA_BUILD_CONCURRENCY', 1),
    // 30 minutes: comfortably longer than a full multi-arch build.
    lockDuration: intFromEnv('ELA_BUILD_LOCK_DURATION_MS', 30 * 60 * 1000),
    // How often the worker scans for stalled jobs (locks that truly expired).
    stalledInterval: intFromEnv('ELA_BUILD_STALLED_INTERVAL_MS', 30 * 1000),
    // Recover a stalled job a few times before failing it outright.
    maxStalledCount: intFromEnv('ELA_BUILD_MAX_STALLED_COUNT', 3),
  };
}

let queue = null;

/**
 * Lazily create a singleton BullMQ Queue for enqueuing build jobs.
 * The caller is responsible for closeBuildQueue() when done (short-lived CLIs).
 */
function getBuildQueue() {
  if (!queue) {
    queue = new Queue(QUEUE_NAME, { connection: getConnection() });
  }
  return queue;
}

async function closeBuildQueue() {
  if (queue) {
    await queue.close();
    queue = null;
  }
}

module.exports = {
  QUEUE_NAME,
  getConnection,
  getWorkerOptions,
  getBuildQueue,
  closeBuildQueue,
};
