// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const Redis = require('ioredis');
const { getConnection } = require('./queue');

// Out-of-band terminal session snapshot.
//
// The terminal API holds live agent sessions in memory and answers a client's
// "list sessions" via the `ela-terminal-commands` queue worker. That worker is
// serialized (one slow exec blocks everything behind it), so a long-running
// command used to make `GET /terminal/sessions` time out — pure head-of-line
// blocking, even though listing sessions touches no device.
//
// To decouple the read path from that worker, the terminal API publishes its
// current session list to a Redis key on every change (and on a short refresh
// interval); the client API reads that snapshot directly. If no fresh snapshot
// exists (terminal API down, or an older build without a publisher), readers
// fall back to the queue, preserving the previous behaviour.

function intFromEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

const SESSION_SNAPSHOT_KEY = process.env.ELA_SESSION_SNAPSHOT_KEY || 'ela:terminal:sessions';

// How long a published snapshot lives in Redis. The publisher refreshes well
// within this window; once it stops (process gone) the key expires and readers
// fall back to the queue. Kept comfortably above the refresh interval so a
// transient hiccup does not evict a still-valid snapshot.
const SNAPSHOT_TTL_SECONDS = intFromEnv('ELA_SESSION_SNAPSHOT_TTL_SEC', 15);

// A reader treats a snapshot older than this as stale and falls back to the
// queue. Slightly below the TTL so we never serve a snapshot Redis is about to
// evict out from under us.
const SNAPSHOT_STALE_MS = intFromEnv('ELA_SESSION_SNAPSHOT_STALE_MS', 12000);

let client = null;

function getClient() {
  if (!client) {
    const conn = getConnection();
    client = new Redis({
      host: conn.host,
      port: conn.port,
      // These get/set calls are best-effort: on any Redis trouble the caller
      // catches and falls back to the queue, so we neither want infinite
      // command queuing nor an unhandled 'error' crashing the process.
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
    });
    client.on('error', () => {
      // Swallow: reads/writes are wrapped in try/catch by callers, which fall
      // back to the queue path. An unhandled 'error' event would crash Node.
    });
  }
  return client;
}

/**
 * Publish the current session list. Overwrites the previous snapshot and
 * (re)sets its TTL. Best-effort — rejects on Redis failure so the caller can
 * log; it must not be treated as fatal.
 *
 * @param {Array<object>} sessions  Session descriptors (see commandWorker.buildSessionList).
 */
async function publishSessionSnapshot(sessions, { now = Date.now } = {}) {
  const payload = JSON.stringify({ sessions: sessions || [], updatedAt: now() });
  await getClient().set(SESSION_SNAPSHOT_KEY, payload, 'EX', SNAPSHOT_TTL_SECONDS);
}

/**
 * Read the raw snapshot. Returns `{ sessions, updatedAt, ageMs }` or null when
 * the key is missing/unparseable. Does not apply the staleness policy — use
 * readFreshSessionSnapshot for the "usable or fall back" decision.
 */
async function readSessionSnapshot({ now = Date.now } = {}) {
  const raw = await getClient().get(SESSION_SNAPSHOT_KEY);
  if (!raw) return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || !Array.isArray(parsed.sessions)) return null;
  const updatedAt = Number(parsed.updatedAt) || 0;
  return { sessions: parsed.sessions, updatedAt, ageMs: now() - updatedAt };
}

/**
 * Read the snapshot only if it is fresh enough to serve. Returns the session
 * array, or null when there is no snapshot or it is stale (caller should fall
 * back to the command queue).
 */
async function readFreshSessionSnapshot(opts = {}) {
  const snap = await readSessionSnapshot(opts);
  if (!snap) return null;
  if (snap.ageMs > SNAPSHOT_STALE_MS) return null;
  return snap.sessions;
}

async function closeSnapshotClient() {
  if (client) {
    const c = client;
    client = null;
    try {
      await c.quit();
    } catch {
      c.disconnect();
    }
  }
}

module.exports = {
  SESSION_SNAPSHOT_KEY,
  SNAPSHOT_TTL_SECONDS,
  SNAPSHOT_STALE_MS,
  publishSessionSnapshot,
  readSessionSnapshot,
  readFreshSessionSnapshot,
  closeSnapshotClient,
};
