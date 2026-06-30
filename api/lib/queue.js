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
  getBuildQueue,
  closeBuildQueue,
};
