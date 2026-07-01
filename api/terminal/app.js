// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const express = require('express');

/**
 * Build the terminal server's HTTP app. The terminal API is **agent-only**: the
 * only client of this process is the agent WebSocket (`/terminal/<mac>`, handled
 * by the WebSocket server, not this app) and, internally, the operator-command
 * queue worker. The HTTP surface here is therefore just:
 *   GET /terminal/healthcheck   (always public)
 *   everything else             404
 *
 * Operator control (sessions/exec/spawn) lives on the client API now; it reaches
 * agents by enqueuing commands this process's worker executes (see
 * api/terminal/commandWorker.js and api/client/routes/terminal.js).
 *
 * @param {object} deps
 * @param {Array}    [deps.blockedCidrs]
 * @param {Function} [deps.isBlocked]           (remoteAddress, blockedCidrs) => boolean.
 * @param {Function} [deps.resolveRemoteAddress] (req) => string.
 * @returns {import('express').Express}
 */
function createTerminalApp(deps = {}) {
  const {
    blockedCidrs = [],
    isBlocked = () => false,
    resolveRemoteAddress = (req) => (req.socket && req.socket.remoteAddress) || '',
  } = deps;

  const app = express();
  app.disable('x-powered-by');

  // Always-public liveness check, registered before the block guard.
  app.get('/terminal/healthcheck', (req, res) => {
    res.type('text/plain').send('ok');
  });

  // Reject blocked remotes for anything past the healthcheck.
  app.use((req, res, next) => {
    if (isBlocked(resolveRemoteAddress(req), blockedCidrs)) {
      res.status(403).type('text/plain').send('Forbidden');
      return;
    }
    next();
  });

  app.use((req, res) => {
    res.status(404).type('text/plain').send('Not Found');
  });

  return app;
}

module.exports = {
  createTerminalApp,
};
