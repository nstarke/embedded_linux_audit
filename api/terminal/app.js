// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const express = require('express');
const auth = require('../auth');
const { runExec } = require('./execCommand');

const MAC_ADDRESS_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_EXEC_TIMEOUT_MS = 60000;

/**
 * Build the ExpressJS application that serves the terminal server's HTTP API.
 *
 * The same `http.Server` that runs this app also carries the WebSocket
 * upgrade handler, so the routes here only cover the JSON control API:
 *   GET  /terminal/healthcheck   (always public)
 *   GET  /terminal/sessions      (auth required when enforced)
 *   POST /terminal/:mac/exec     (auth required when enforced)
 *
 * @param {object} deps
 * @param {object} deps.sessionRegistry  Live session registry.
 * @param {Array}  [deps.blockedCidrs]   Parsed blocked CIDR list.
 * @param {Function} [deps.isBlocked]    (remoteAddress, blockedCidrs) => boolean.
 * @param {Function} [deps.resolveRemoteAddress] (req) => string.
 * @param {Function} [deps.runExecImpl]  Override for runExec (tests).
 * @param {Function} [deps.authMiddleware] Override for auth.middleware (tests).
 * @returns {import('express').Express}
 */
function createTerminalApp(deps = {}) {
  const {
    sessionRegistry = null,
    blockedCidrs = [],
    isBlocked = () => false,
    resolveRemoteAddress = (req) => (req.socket && req.socket.remoteAddress) || '',
    runExecImpl = runExec,
    authMiddleware = auth.middleware,
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

  app.get('/terminal/sessions', authMiddleware, (req, res) => {
    const sessions = sessionRegistry.entries().map(([mac, entry]) => ({
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

  // Parse the JSON body regardless of Content-Type, capping it at 1 MiB to
  // mirror the old manual reader.  Body-parser failures are translated to the
  // legacy error shapes by the error handler at the bottom of the stack.
  const parseExecBody = express.json({ limit: MAX_BODY_BYTES, type: () => true });

  app.post('/terminal/:mac/exec', authMiddleware, validateMac, parseExecBody, async (req, res) => {
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
