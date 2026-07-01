// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const express = require('express');

const MAC_ADDRESS_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_EXEC_TIMEOUT_MS = 60000;
const DEFAULT_EXEC_TIMEOUT_MS = 15000;
// How long to wait for the terminal worker's reply beyond the command's own
// timeout, to absorb queue + execution overhead.
const WAIT_MARGIN_MS = 10000;
const DEFAULT_WAIT_MS = 30000;

// Lazily resolve the DB helpers so importing this module (e.g. in tests) does
// not pull in db/index and the real sequelize.
function deviceRegistry() {
  return require('../../lib/db/deviceRegistry');
}

function defaultSendCommand(payload, opts) {
  return require('../../lib/queue').sendTerminalCommand(payload, opts);
}

/**
 * Register the operator terminal-control routes on the client API. Every route
 * is scoped to the authenticated user (the client app enforces `req.authUser`
 * before these run) AND ACL'd to devices that user is associated with
 * (`user_devices`): a device the caller is not associated with is treated as
 * not connected (404), so the API never touches or reveals other users' devices.
 *
 * Commands are not executed here — they are handed to the terminal API over the
 * `ela-terminal-commands` queue and the result is awaited and relayed back.
 *
 * @param {object} app
 * @param {object} deps
 * @param {Function} [deps.sendCommand]  (payload, {waitMs}) => Promise<{status, body}>.
 * @param {Function} [deps.isUserAssociatedWithDevice]
 * @param {Function} [deps.listUserDeviceMacs]
 */
function registerTerminalRoutes(app, deps = {}) {
  const {
    sendCommand = defaultSendCommand,
    isUserAssociatedWithDevice = (username, mac) => deviceRegistry().isUserAssociatedWithDevice(username, mac),
    listUserDeviceMacs = (username) => deviceRegistry().listUserDeviceMacs(username),
  } = deps;

  const parseBody = express.json({ limit: MAX_BODY_BYTES, type: () => true });

  function validateMac(req, res, next) {
    const mac = String(req.params.mac || '').toLowerCase();
    if (!MAC_ADDRESS_RE.test(mac)) {
      res.status(400).json({ error: 'invalid mac address' });
      return;
    }
    req.normalizedMac = mac;
    next();
  }

  // ACL: the caller must be associated with the target device. Not associated
  // is reported exactly like "no session" so devices cannot be enumerated.
  async function requireDeviceAssociation(req, res, next) {
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

  // Enqueue a command, await the terminal worker's result, and relay it. A wait
  // failure (worker down or slow) surfaces as 504.
  async function dispatch(res, payload, waitMs) {
    let result;
    try {
      result = await sendCommand(payload, { waitMs });
    } catch {
      res.status(504).json({ error: 'terminal command timed out or terminal API unavailable' });
      return;
    }
    res.status(result.status).json(result.body);
  }

  // GET /terminal/sessions — only the caller's associated devices.
  app.get('/terminal/sessions', async (req, res) => {
    let allowed;
    try {
      allowed = new Set(await listUserDeviceMacs(req.authUser));
    } catch {
      res.status(500).json({ error: 'internal error' });
      return;
    }

    let result;
    try {
      result = await sendCommand({ type: 'sessions' }, { waitMs: DEFAULT_WAIT_MS });
    } catch {
      res.status(504).json({ error: 'terminal command timed out or terminal API unavailable' });
      return;
    }
    if (result.status !== 200) {
      res.status(result.status).json(result.body);
      return;
    }
    const sessions = (result.body.sessions || []).filter((s) => allowed.has(s.mac));
    res.status(200).json({ sessions });
  });

  app.post('/terminal/:mac/exec', validateMac, requireDeviceAssociation, parseBody, async (req, res) => {
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

    const waitMs = (timeoutMs || DEFAULT_EXEC_TIMEOUT_MS) + WAIT_MARGIN_MS;
    await dispatch(res, { type: 'exec', mac: req.normalizedMac, command, timeoutMs }, waitMs);
  });

  app.post('/terminal/:mac/spawn', validateMac, requireDeviceAssociation, parseBody, async (req, res) => {
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

    await dispatch(res, { type: 'spawn', mac: req.normalizedMac, command, args, port }, DEFAULT_WAIT_MS);
  });

  app.get('/terminal/:mac/spawn', validateMac, requireDeviceAssociation, async (req, res) => {
    await dispatch(res, { type: 'listSpawns', mac: req.normalizedMac }, DEFAULT_WAIT_MS);
  });

  app.delete('/terminal/:mac/spawn/:pid', validateMac, requireDeviceAssociation, async (req, res) => {
    const pid = Number(req.params.pid);
    if (!Number.isInteger(pid) || pid <= 0) {
      res.status(400).json({ error: 'invalid pid' });
      return;
    }
    await dispatch(res, { type: 'killSpawn', mac: req.normalizedMac, pid }, DEFAULT_WAIT_MS);
  });
}

module.exports = registerTerminalRoutes;
module.exports.MAC_ADDRESS_RE = MAC_ADDRESS_RE;
module.exports.MAX_EXEC_TIMEOUT_MS = MAX_EXEC_TIMEOUT_MS;
