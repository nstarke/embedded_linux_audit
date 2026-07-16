'use strict';

const { Queue, QueueEvents } = require('bullmq');

// Shared BullMQ definition used by the producer (tools/add-user-key.js) and the
// builder worker (api/builder/worker.js). Per-user binary builds are enqueued
// here so the API never has to compile anything itself.
const QUEUE_NAME = process.env.ELA_BUILD_QUEUE_NAME || 'ela-binary-builds';

// Operator-command request/reply queue: the client API enqueues a command and
// awaits its result; the terminal API worker executes it against the live agent
// session and returns the result (BullMQ job return value). This is how the
// client API reaches agents without the terminal API exposing any client REST.
const COMMAND_QUEUE_NAME = process.env.ELA_COMMAND_QUEUE_NAME || 'ela-terminal-commands';

// GDB command request/reply queue: the client API enqueues a query (e.g. list
// active gdbserver sessions) and awaits its result; the GDB bridge API worker
// answers it from its in-memory session map. Mirrors the terminal command queue
// so the client API can reach the GDB bridge's live state without the GDB API
// exposing any client REST of its own.
const GDB_COMMAND_QUEUE_NAME = process.env.ELA_GDB_COMMAND_QUEUE_NAME || 'ela-gdb-commands';

// Kernel-module build queue: the client API enqueues a build request (device
// kernel facts from a module-buildinfo upload) and the builder worker compiles
// kmod/ against the matching upstream kernel. Separate from the binary-build
// queue so a slow kernel modules_prepare never blocks launcher rebuilds.
const MODULE_BUILD_QUEUE_NAME = process.env.ELA_MODULE_BUILD_QUEUE_NAME || 'ela-module-builds';

// Ghidra-analysis queue: the client API enqueues one job per device rootfs
// decompilation request; the ghidra-analysis worker (api/ghidra/worker.js)
// drives the whole run — pulling the filesystem via `linux remote-copy` and
// decompiling every ELF with analyzeHeadless. Separate from the module-build
// queue so a multi-hour decompile never blocks kernel-module compiles.
const GHIDRA_ANALYSIS_QUEUE_NAME = process.env.ELA_GHIDRA_QUEUE_NAME || 'ela-ghidra-analysis';

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

/* -------------------------------------------------------------------------
 * Kernel-module build queue
 * ---------------------------------------------------------------------- */

let moduleBuildQueue = null;

function getModuleBuildQueue() {
  if (!moduleBuildQueue) {
    moduleBuildQueue = new Queue(MODULE_BUILD_QUEUE_NAME, { connection: getConnection() });
  }
  return moduleBuildQueue;
}

async function closeModuleBuildQueue() {
  if (moduleBuildQueue) {
    await moduleBuildQueue.close();
    moduleBuildQueue = null;
  }
}

// Worker options for module builds. Same long-build reasoning as the binary
// builder (see getWorkerOptions): a cold-cache modules_prepare can run for
// several minutes, so the lock ceiling stays high. Concurrency 1 because
// concurrent builds of the same (version, arch, config) key would race on the
// shared prepared-tree cache.
function getModuleBuildWorkerOptions() {
  return {
    connection: getConnection(),
    concurrency: intFromEnv('ELA_MODULE_BUILD_CONCURRENCY', 1),
    lockDuration: intFromEnv('ELA_MODULE_BUILD_LOCK_DURATION_MS', 30 * 60 * 1000),
    stalledInterval: intFromEnv('ELA_MODULE_BUILD_STALLED_INTERVAL_MS', 30 * 1000),
    maxStalledCount: intFromEnv('ELA_MODULE_BUILD_MAX_STALLED_COUNT', 3),
  };
}

/* -------------------------------------------------------------------------
 * Ghidra-analysis queue
 * ---------------------------------------------------------------------- */

let ghidraAnalysisQueue = null;

function getGhidraAnalysisQueue() {
  if (!ghidraAnalysisQueue) {
    ghidraAnalysisQueue = new Queue(GHIDRA_ANALYSIS_QUEUE_NAME, { connection: getConnection() });
  }
  return ghidraAnalysisQueue;
}

async function closeGhidraAnalysisQueue() {
  if (ghidraAnalysisQueue) {
    await ghidraAnalysisQueue.close();
    ghidraAnalysisQueue = null;
  }
}

// Worker options for ghidra-analysis jobs. A single job first pulls a whole
// device rootfs over the live agent session (`linux remote-copy --recursive /`)
// and then runs analyzeHeadless once per ELF — both open-ended and easily
// multi-hour on a large filesystem or slow link. lockDuration is therefore very
// high so a slow-but-healthy job is never declared stalled; concurrency 1
// because analyzeHeadless is memory-heavy and the jobs share the /data volume.
// All env-overridable.
function getGhidraAnalysisWorkerOptions() {
  return {
    connection: getConnection(),
    concurrency: intFromEnv('ELA_GHIDRA_CONCURRENCY', 1),
    // 6 hours: comfortably longer than a full rootfs copy + decompile.
    lockDuration: intFromEnv('ELA_GHIDRA_LOCK_DURATION_MS', 6 * 60 * 60 * 1000),
    stalledInterval: intFromEnv('ELA_GHIDRA_STALLED_INTERVAL_MS', 60 * 1000),
    maxStalledCount: intFromEnv('ELA_GHIDRA_MAX_STALLED_COUNT', 2),
  };
}

/* -------------------------------------------------------------------------
 * Terminal command request/reply queue
 * ---------------------------------------------------------------------- */

let commandQueue = null;
let commandQueueEvents = null;

function getCommandQueue() {
  if (!commandQueue) {
    commandQueue = new Queue(COMMAND_QUEUE_NAME, { connection: getConnection() });
  }
  return commandQueue;
}

// Shared QueueEvents stream used to await a job's completion (request/reply).
function getCommandQueueEvents() {
  if (!commandQueueEvents) {
    commandQueueEvents = new QueueEvents(COMMAND_QUEUE_NAME, { connection: getConnection() });
  }
  return commandQueueEvents;
}

// BullMQ Worker options for the terminal command worker.
//
// `runExec` detects completion by watching a session's shared output stream, so
// two commands against the SAME device would corrupt each other. That used to
// force global concurrency 1 — but then one slow exec (e.g. a full-rootfs
// `remote-copy`) blocked every other device's commands AND the sessions
// listing, timing operators out. The worker now enforces per-device isolation
// itself (commandWorker.withDeviceLock: device-touching commands serialize per
// MAC, control-plane commands never block), so it is safe to run concurrently.
// Different devices proceed in parallel; a device's own commands still queue.
// Env-overridable.
function getCommandWorkerOptions() {
  return {
    connection: getConnection(),
    concurrency: intFromEnv('ELA_TERMINAL_CONCURRENCY', 8),
  };
}

/**
 * Enqueue an operator command and wait for the terminal worker's result.
 * Returns the worker's return value (`{ status, body }`). Rejects if the wait
 * exceeds `waitMs` (e.g. the terminal worker is down) or the job fails.
 *
 * @param {object} payload  { type, mac, ... } — see api/terminal/commandWorker.js.
 * @param {{waitMs?: number}} [opts]
 */
async function sendTerminalCommand(payload, { waitMs = 30000 } = {}) {
  const q = getCommandQueue();
  const events = getCommandQueueEvents();
  await events.waitUntilReady();
  const job = await q.add(payload.type || 'command', payload, {
    removeOnComplete: true,
    removeOnFail: true,
  });
  return job.waitUntilFinished(events, waitMs);
}

async function closeCommandQueue() {
  if (commandQueueEvents) {
    await commandQueueEvents.close();
    commandQueueEvents = null;
  }
  if (commandQueue) {
    await commandQueue.close();
    commandQueue = null;
  }
}

/* -------------------------------------------------------------------------
 * GDB command request/reply queue
 * ---------------------------------------------------------------------- */

let gdbCommandQueue = null;
let gdbCommandQueueEvents = null;

function getGdbCommandQueue() {
  if (!gdbCommandQueue) {
    gdbCommandQueue = new Queue(GDB_COMMAND_QUEUE_NAME, { connection: getConnection() });
  }
  return gdbCommandQueue;
}

function getGdbCommandQueueEvents() {
  if (!gdbCommandQueueEvents) {
    gdbCommandQueueEvents = new QueueEvents(GDB_COMMAND_QUEUE_NAME, { connection: getConnection() });
  }
  return gdbCommandQueueEvents;
}

// GDB command worker options. These queries only read the in-memory session
// map, so concurrency can be higher than the terminal worker's; default 4,
// env-overridable.
function getGdbCommandWorkerOptions() {
  return {
    connection: getConnection(),
    concurrency: intFromEnv('ELA_GDB_CONCURRENCY', 4),
  };
}

/**
 * Enqueue a GDB bridge query and wait for the GDB worker's result. Returns the
 * worker's return value (`{ status, body }`). Rejects if the wait exceeds
 * `waitMs` (e.g. the GDB API is down) or the job fails.
 *
 * @param {object} payload  { type, ... } — see api/gdb/commandWorker.js.
 * @param {{waitMs?: number}} [opts]
 */
async function sendGdbCommand(payload, { waitMs = 30000 } = {}) {
  const q = getGdbCommandQueue();
  const events = getGdbCommandQueueEvents();
  await events.waitUntilReady();
  const job = await q.add(payload.type || 'command', payload, {
    removeOnComplete: true,
    removeOnFail: true,
  });
  return job.waitUntilFinished(events, waitMs);
}

async function closeGdbCommandQueue() {
  if (gdbCommandQueueEvents) {
    await gdbCommandQueueEvents.close();
    gdbCommandQueueEvents = null;
  }
  if (gdbCommandQueue) {
    await gdbCommandQueue.close();
    gdbCommandQueue = null;
  }
}

module.exports = {
  QUEUE_NAME,
  COMMAND_QUEUE_NAME,
  GDB_COMMAND_QUEUE_NAME,
  MODULE_BUILD_QUEUE_NAME,
  GHIDRA_ANALYSIS_QUEUE_NAME,
  getConnection,
  getWorkerOptions,
  getBuildQueue,
  closeBuildQueue,
  getModuleBuildQueue,
  closeModuleBuildQueue,
  getModuleBuildWorkerOptions,
  getGhidraAnalysisQueue,
  closeGhidraAnalysisQueue,
  getGhidraAnalysisWorkerOptions,
  getCommandQueue,
  getCommandQueueEvents,
  getCommandWorkerOptions,
  sendTerminalCommand,
  closeCommandQueue,
  getGdbCommandQueue,
  getGdbCommandQueueEvents,
  getGdbCommandWorkerOptions,
  sendGdbCommand,
  closeGdbCommandQueue,
};
