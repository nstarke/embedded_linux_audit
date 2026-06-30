// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const express = require('express');
const auth = require('../auth');
const { runExec } = require('./execCommand');
const { runSpawn } = require('./spawnCommand');

// The DB layer is required lazily (only when an authenticated user is actually
// resolved) so that merely importing this module does not pull in db/index and
// the real sequelize — keeping the app importable in isolation and in tests.
function deviceRegistry() {
  return require('../lib/db/deviceRegistry');
}

const MAC_ADDRESS_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_EXEC_TIMEOUT_MS = 60000;

/**
 * Build the ExpressJS application that serves the terminal server's HTTP API.
 *
 * The same `http.Server` that runs this app also carries the WebSocket
 * upgrade handler, so the routes here only cover the JSON control API:
 *   GET    /terminal/healthcheck        (always public)
 *   GET    /terminal/sessions           (auth required when enforced)
 *   POST   /terminal/:mac/exec          (auth required when enforced)
 *   POST   /terminal/:mac/spawn         (auth required when enforced)
 *   GET    /terminal/:mac/spawn         (auth required when enforced)
 *   DELETE /terminal/:mac/spawn/:pid    (auth required when enforced)
 *
 * When auth resolves a user, the per-device routes and the sessions listing are
 * restricted to devices that user is associated with (user_devices). Devices the
 * user is not associated with are treated as not connected (404), so the API
 * never exposes other users' devices.
 *
 * @param {object} deps
 * @param {object} deps.sessionRegistry  Live session registry.
 * @param {Array}  [deps.blockedCidrs]   Parsed blocked CIDR list.
 * @param {Function} [deps.isBlocked]    (remoteAddress, blockedCidrs) => boolean.
 * @param {Function} [deps.resolveRemoteAddress] (req) => string.
 * @param {Function} [deps.runExecImpl]  Override for runExec (tests).
 * @param {Function} [deps.runSpawnImpl] Override for runSpawn (tests).
 * @param {Function} [deps.now]          Clock returning the spawn start time.
 * @param {Function} [deps.authMiddleware] Override for auth.middleware (tests).
 * @param {Function} [deps.isUserAssociatedWithDevice] (username, mac) => Promise<boolean>.
 * @param {Function} [deps.listUserDeviceMacs] (username) => Promise<string[]>.
 * @returns {import('express').Express}
 */
function createTerminalApp(deps = {}) {
  const {
    sessionRegistry = null,
    blockedCidrs = [],
    isBlocked = () => false,
    resolveRemoteAddress = (req) => (req.socket && req.socket.remoteAddress) || '',
    runExecImpl = runExec,
    runSpawnImpl = runSpawn,
    now = () => new Date().toISOString(),
    authMiddleware = auth.middleware,
    isUserAssociatedWithDevice = (username, mac) => deviceRegistry().isUserAssociatedWithDevice(username, mac),
    listUserDeviceMacs = (username) => deviceRegistry().listUserDeviceMacs(username),
  } = deps;

  const app = express();
  app.disable('x-powered-by');

  // The healthcheck is always public.  It is registered before the block and
  // auth middleware so it answers even for blocked or unauthenticated clients.
  app.get('/terminal/healthcheck', (req, res) => {
    res.type('text/plain').send('ok');
  });

  // Reject blocked remotes for every route except the healthcheck above.
  app.use((req, res, next) => {
    if (isBlocked(resolveRemoteAddress(req), blockedCidrs)) {
      res.status(403).type('text/plain').send('Forbidden');
      return;
    }
    next();
  });

  app.get('/terminal/sessions', authMiddleware, async (req, res) => {
    let entries = sessionRegistry.entries();

    // Expose only devices the authenticated user is associated with (via
    // user_devices). When auth is open (no resolved user) the API stays open
    // and lists every live session, matching the rest of the auth posture.
    if (req.authUser) {
      let allowed;
      try {
        allowed = new Set(await listUserDeviceMacs(req.authUser));
      } catch {
        res.status(500).json({ error: 'internal error' });
        return;
      }
      entries = entries.filter(([mac]) => allowed.has(mac));
    }

    const sessions = entries.map(([mac, entry]) => ({
      mac,
      alias: entry.alias || null,
      group: entry.group || null,
      remoteAddress: entry.remoteAddress || null,
      connectedAt: entry.connectedAt || null,
      lastHeartbeat: entry.lastHeartbeat || null,
    }));
    res.status(200).json(sessions);
  });

  // Validate the MAC before parsing the body so a malformed MAC is rejected
  // even when the request carries an oversized or invalid payload — matching
  // the ordering of the previous hand-rolled handler.
  function validateMac(req, res, next) {
    const mac = String(req.params.mac || '').toLowerCase();
    if (!MAC_ADDRESS_RE.test(mac)) {
      res.status(400).json({ error: 'invalid mac address' });
      return;
    }
    req.normalizedMac = mac;
    next();
  }

  // Restrict the per-device routes to devices the authenticated user is
  // associated with. A device the user is not associated with is treated as if
  // it were not connected (404, same body as a missing session) so the API does
  // not expose or enumerate other users' devices. Skipped in open mode (no
  // resolved user), matching the rest of the auth posture.
  async function requireDeviceAssociation(req, res, next) {
    if (!req.authUser) {
      next();
      return;
    }
    let associated;
    try {
      associated = await isUserAssociatedWithDevice(req.authUser, req.normalizedMac);
    } catch {
      res.status(500).json({ error: 'internal error' });
      return;
    }
    if (!associated) {
      res.status(404).json({ error: 'no active session for mac' });
      return;
    }
    next();
  }

  // Parse the JSON body regardless of Content-Type, capping it at 1 MiB to
  // mirror the old manual reader.  Body-parser failures are translated to the
  // legacy error shapes by the error handler at the bottom of the stack.
  const parseExecBody = express.json({ limit: MAX_BODY_BYTES, type: () => true });

  app.post('/terminal/:mac/exec', authMiddleware, validateMac, requireDeviceAssociation, parseExecBody, async (req, res) => {
    const mac = req.normalizedMac;
    const body = req.body || {};

    const command = typeof body.command === 'string' ? body.command : '';
    if (!command.trim()) {
      res.status(400).json({ error: 'command is required' });
      return;
    }

    let timeoutMs;
    if (body.timeoutMs !== undefined && body.timeoutMs !== null) {
      timeoutMs = Number(body.timeoutMs);
      if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_EXEC_TIMEOUT_MS) {
        res.status(400).json({ error: `timeoutMs must be a positive integer <= ${MAX_EXEC_TIMEOUT_MS}` });
        return;
      }
    }

    const entry = sessionRegistry.getSession(mac);
    if (!entry) {
      res.status(404).json({ error: 'no active session for mac' });
      return;
    }

    try {
      const result = await runExecImpl({ entry, mac, command, timeoutMs });
      res.status(200).json({ ok: true, output: result.output, durationMs: result.durationMs });
    } catch (err) {
      if (err.code === 'TIMEOUT') {
        res.status(504).json({
          ok: false,
          error: 'exec timed out',
          output: err.output || '',
          durationMs: err.durationMs,
        });
        return;
      }
      if (err.code === 'NOT_CONNECTED') {
        res.status(404).json({ error: 'no active session for mac' });
        return;
      }
      res.status(500).json({ error: 'exec failed' });
    }
  });

  // Lazily attach a spawn registry to a session entry.  Entries created by the
  // live sessionRegistry already carry a `spawns` Map; this guards against
  // entries that predate the field (or are minted by tests).
  function spawnsFor(entry) {
    if (!entry.spawns) {
      entry.spawns = new Map();
    }
    return entry.spawns;
  }

  function serializeSpawn(record) {
    const out = {
      pid: record.pid,
      command: record.command,
      args: record.args,
      startedAt: record.startedAt,
    };
    if (record.port !== undefined) {
      out.port = record.port;
    }
    return out;
  }

  // Launch a long-running process (e.g. gdbserver, an SSH tunnel) on the agent
  // and track it so it can be listed and killed later.
  app.post('/terminal/:mac/spawn', authMiddleware, validateMac, requireDeviceAssociation, parseExecBody, async (req, res) => {
    const mac = req.normalizedMac;
    const body = req.body || {};

    const command = typeof body.command === 'string' ? body.command : '';
    if (!command.trim()) {
      res.status(400).json({ error: 'command is required' });
      return;
    }

    let args = [];
    if (body.args !== undefined && body.args !== null) {
      if (!Array.isArray(body.args) || !body.args.every((a) => typeof a === 'string')) {
        res.status(400).json({ error: 'args must be an array of strings' });
        return;
      }
      args = body.args;
    }

    let port;
    if (body.port !== undefined && body.port !== null) {
      port = Number(body.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        res.status(400).json({ error: 'port must be an integer between 1 and 65535' });
        return;
      }
    }

    const entry = sessionRegistry.getSession(mac);
    if (!entry) {
      res.status(404).json({ error: 'no active session for mac' });
      return;
    }

    try {
      const result = await runSpawnImpl({ entry, mac, command, args, port });
      const record = {
        pid: result.pid,
        command,
        args,
        port: result.port,
        startedAt: now(),
      };
      spawnsFor(entry).set(result.pid, record);

      const response = { pid: result.pid };
      if (result.port !== undefined) {
        response.port = result.port;
      }
      res.status(201).json(response);
    } catch (err) {
      if (err.code === 'TIMEOUT') {
        res.status(504).json({ error: 'spawn timed out' });
        return;
      }
      if (err.code === 'NOT_CONNECTED') {
        res.status(404).json({ error: 'no active session for mac' });
        return;
      }
      res.status(500).json({ error: 'spawn failed' });
    }
  });

  // List the live spawns tracked for a session.
  app.get('/terminal/:mac/spawn', authMiddleware, validateMac, requireDeviceAssociation, (req, res) => {
    const entry = sessionRegistry.getSession(req.normalizedMac);
    if (!entry) {
      res.status(404).json({ error: 'no active session for mac' });
      return;
    }
    const spawns = [...spawnsFor(entry).values()].map(serializeSpawn);
    res.status(200).json(spawns);
  });

  // Kill a tracked spawn and drop it from the registry.
  app.delete('/terminal/:mac/spawn/:pid', authMiddleware, validateMac, requireDeviceAssociation, async (req, res) => {
    const pid = Number(req.params.pid);
    if (!Number.isInteger(pid) || pid <= 0) {
      res.status(400).json({ error: 'invalid pid' });
      return;
    }

    const entry = sessionRegistry.getSession(req.normalizedMac);
    if (!entry) {
      res.status(404).json({ error: 'no active session for mac' });
      return;
    }

    const spawns = spawnsFor(entry);
    if (!spawns.has(pid)) {
      res.status(404).json({ error: 'no such spawn' });
      return;
    }

    try {
      await runExecImpl({ entry, mac: req.normalizedMac, command: `kill ${pid}` });
      spawns.delete(pid);
      res.status(200).json({ ok: true });
    } catch (err) {
      if (err.code === 'NOT_CONNECTED') {
        res.status(404).json({ error: 'no active session for mac' });
        return;
      }
      res.status(500).json({ error: 'kill failed' });
    }
  });

  app.use((req, res) => {
    res.status(404).type('text/plain').send('Not Found');
  });

  // Translate body-parser failures back into the legacy error responses.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err && err.type === 'entity.too.large') {
      res.status(413).json({ error: 'payload too large' });
      return;
    }
    if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError)) {
      res.status(400).json({ error: 'invalid JSON body' });
      return;
    }
    res.status(500).json({ error: 'internal error' });
  });

  return app;
}

module.exports = {
  createTerminalApp,
  MAC_ADDRESS_RE,
  MAX_BODY_BYTES,
};
