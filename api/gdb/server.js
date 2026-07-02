// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const http = require('http');
const { WebSocketServer } = require('ws');
const { Worker } = require('bullmq');
const auth = require('../auth');
const { parseGdbUrl } = require('./urlParser');
const { createSessionManager } = require('./sessionManager');
const { GDB_COMMAND_QUEUE_NAME, getGdbCommandWorkerOptions } = require('../lib/queue');
const { processGdbCommand } = require('./commandWorker');
const { initializeDatabase, runMigrations, closeDatabase } = require('../lib/db');
const { loadApiKeyHashes, isUserAssociatedWithDevice } = require('../lib/db/deviceRegistry');

const PORT = parseInt(process.env.ELA_GDB_PORT || '9000', 10);
const HOST = process.env.ELA_GDB_HOST || '0.0.0.0';

/*
 * Session map: hexkey (32 hex chars) ->
 *   { in: WebSocket|null, out: WebSocket|null, deviceMac: string|null }
 *
 * The embedded agent connects to  /gdb/in/<hexkey>?mac=<mac>  (RSP from
 * gdbserver); the MAC identifies the device the session belongs to.
 * gdb-multiarch connects to       /gdb/out/<hexkey>  via:
 *   target remote wss://HOST/gdb/out/<hexkey>
 *
 * Binary frames are forwarded bidirectionally between the two sides.
 * When the 'in' (agent) side closes, the session is torn down entirely.
 */
const sm = createSessionManager();
const sessions = sm.sessions;

// Answers client-API queries (e.g. list active sessions) from the in-memory
// session map above, over the shared BullMQ queue. Assigned in main().
let commandWorker = null;

/*
 * The two ends of a GDB tunnel authenticate with different token scopes, read
 * from the database per connection:
 *   - /gdb/in/<key>  (agent pushing the gdbserver RSP) uses an AGENT key.
 *   - /gdb/out/<key> (operator running the remote gdb session) uses a CLIENT
 *     key — the same key used for the client API.
 * Enforcement is dynamic: a direction is gated once at least one key of its
 * scope exists, open otherwise (resolveBearer with enforced=false).
 *
 * The out side is additionally gated by device association: when the operator's
 * client token resolves to a username, that user must be associated (via
 * user_devices, i.e. have phoned the device into the terminal API) with the
 * device the agent declared on the in side of the same session. With no client
 * keys configured (open mode, resolveBearer === true) there is no user to scope
 * by and the association check is skipped, matching the open-auth posture.
 */
const httpServer = http.createServer((_req, res) => {
  res.writeHead(404);
  res.end('Not Found');
});

const wss = new WebSocketServer({
  server: httpServer,
  verifyClient(info, done) {
    const parsed = parseGdbUrl(info.req.url || '');
    if (!parsed) {
      done(false, 404, 'Not Found');
      return;
    }
    const scope = parsed.direction === 'in' ? 'agent' : 'client';
    auth.resolveBearer(info.req.headers.authorization, () => loadApiKeyHashes(scope), false)
      .then(async (authResult) => {
        if (!authResult) {
          done(false, 401, 'Unauthorized');
          return;
        }
        // The operator (out) side may only attach to a session whose device the
        // operator's user is associated with. Skipped in open mode, where there
        // is no resolved username (authResult === true).
        if (parsed.direction === 'out' && typeof authResult === 'string') {
          const session = sessions.get(parsed.hexkey);
          const deviceMac = session && session.deviceMac;
          if (!deviceMac || !(await isUserAssociatedWithDevice(authResult, deviceMac))) {
            done(false, 403, 'Forbidden');
            return;
          }
        }
        done(true);
      })
      .catch(() => done(false, 401, 'Unauthorized'));
  },
});

wss.on('connection', (ws, req) => {
  const parsed = parseGdbUrl(req.url || '');
  if (!parsed) { ws.close(); return; }

  const direction = parsed.direction; // 'in' (agent) or 'out' (GDB)
  const hexkey    = parsed.hexkey;
  const peer      = direction === 'in' ? 'out' : 'in';

  const s = sm.getOrCreate(hexkey);

  // The agent (in) side declares the device MAC; record it so the out side's
  // handshake can verify the operator is associated with this device.
  if (direction === 'in' && parsed.mac) {
    s.deviceMac = parsed.mac;
  }

  if (s[direction]) {
    try { s[direction].close(); } catch {}
  }
  s[direction] = ws;

  ws.on('message', (data) => {
    sm.relay(s[peer], data);
  });

  ws.on('close', () => {
    if (s[direction] === ws) {
      s[direction] = null;
    }
    // Agent disconnect tears down the whole session.
    if (direction === 'in') {
      sm.purge(hexkey, 4001, 'agent disconnected');
    } else if (!s.in && !s.out) {
      sessions.delete(hexkey);
    }
  });

  ws.on('error', () => {
    if (s[direction] === ws) {
      s[direction] = null;
    }
  });
});

process.on('SIGTERM', () => {
  for (const key of sm.keys()) {
    sm.purge(key);
  }
  if (commandWorker) {
    commandWorker.close().catch(() => {});
  }
  httpServer.close(() => process.exit(0));
});

process.on('SIGINT', () => process.exit(0));

async function main() {
  try {
    await initializeDatabase();
    await runMigrations();
  } catch (err) {
    process.stderr.write(`Failed to initialize database: ${err.message}\n`);
    process.exit(1);
    return;
  }

  // Answer client-API queries (list sessions) against the live session map.
  commandWorker = new Worker(
    GDB_COMMAND_QUEUE_NAME,
    (job) => processGdbCommand({ job, sessions }),
    getGdbCommandWorkerOptions(),
  );
  commandWorker.on('error', (err) => {
    process.stderr.write(`gdb command worker error: ${err && err.message}\n`);
  });

  // Keys are read from the database per connection (see verifyClient above), so
  // nothing is loaded here.
  httpServer.listen(PORT, HOST, () => {
    process.stderr.write(`ELA GDB bridge API listening on ws://${HOST}:${PORT}\n`);
  });
}

function start() {
  return main().catch(async (err) => {
    process.stderr.write(`${err.stack || err.message}\n`);
    try {
      await closeDatabase();
    } catch {
      // ignore shutdown errors
    }
    process.exit(1);
  });
}

if (require.main === module) {
  start();
}

module.exports = { httpServer, wss, sessions, main };
