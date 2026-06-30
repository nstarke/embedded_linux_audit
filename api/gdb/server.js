// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const http = require('http');
const { WebSocketServer } = require('ws');
const auth = require('../auth');
const { parseGdbUrl } = require('./urlParser');
const { createSessionManager } = require('./sessionManager');
const { initializeDatabase, runMigrations, closeDatabase } = require('../lib/db');
const { loadApiKeyHashes } = require('../lib/db/deviceRegistry');

const PORT = parseInt(process.env.ELA_GDB_PORT || '9000', 10);
const HOST = process.env.ELA_GDB_HOST || '0.0.0.0';

/*
 * Session map: hexkey (32 hex chars) -> { in: WebSocket|null, out: WebSocket|null }
 *
 * The embedded agent connects to  /gdb/in/<hexkey>  (RSP from gdbserver).
 * gdb-multiarch connects to       /gdb/out/<hexkey>  via:
 *   target remote wss://HOST/gdb/out/<hexkey>
 *
 * Binary frames are forwarded bidirectionally between the two sides.
 * When the 'in' (agent) side closes, the session is torn down entirely.
 */
const sm = createSessionManager();
const sessions = sm.sessions;

/*
 * The two ends of a GDB tunnel authenticate with different token scopes:
 *   - /gdb/in/<key>  (agent pushing the gdbserver RSP) uses an AGENT key.
 *   - /gdb/out/<key> (operator running the remote gdb session) uses a CLIENT
 *     key — the same key used for the client API.
 * Both sets are loaded once at startup (in main); enforcement for a direction
 * is opt-in: a direction is only gated once at least one key of its scope
 * exists, matching the other services.
 */
let agentKeyHashes = [];
let clientKeyHashes = [];

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
    const keyHashes = parsed.direction === 'in' ? agentKeyHashes : clientKeyHashes;
    if (keyHashes.length === 0 || auth.matchBearer(info.req.headers.authorization, keyHashes) !== null) {
      done(true);
    } else {
      done(false, 401, 'Unauthorized');
    }
  },
});

wss.on('connection', (ws, req) => {
  const parsed = parseGdbUrl(req.url || '');
  if (!parsed) { ws.close(); return; }

  const direction = parsed.direction; // 'in' (agent) or 'out' (GDB)
  const hexkey    = parsed.hexkey;
  const peer      = direction === 'in' ? 'out' : 'in';

  const s = sm.getOrCreate(hexkey);

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

  // 'in' (agent gdbserver) is gated by agent-scoped keys; 'out' (operator gdb
  // remote session) is gated by client-scoped keys. Read once at startup.
  agentKeyHashes = await loadApiKeyHashes('agent');
  clientKeyHashes = await loadApiKeyHashes('client');

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
