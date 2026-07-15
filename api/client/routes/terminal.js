// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const express = require('express');

// Accept either separator (aa:bb:.. or aa-bb-..), any case. Devices are stored
// with whatever separator the agent used in its terminal URL (some use `-`), so
// we normalise for comparison and resolve to the actual stored form.
const MAC_ADDRESS_RE = /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/;
const MAX_BODY_BYTES = 1024 * 1024;

// Reduce a MAC to its 12 lowercase hex digits for separator-insensitive
// comparison (`AA-BB-..`, `aa:bb:..`, and `aabb..` all compare equal).
function macKey(mac) {
  return String(mac || '').toLowerCase().replace(/[^0-9a-f]/g, '');
}
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
 * @param {Function} [deps.listUserDeviceMacs] (username) => Promise<string[]> — the
 *   caller's associated device MACs, in their stored form. Used for the ACL and
 *   to resolve a request's MAC to the stored form regardless of separator.
 */
function registerTerminalRoutes(app, deps = {}) {
  const {
    sendCommand = defaultSendCommand,
    listUserDeviceMacs = (username) => deviceRegistry().listUserDeviceMacs(username),
    recordCommandLog = (row) => deviceRegistry().recordCommandLog(row),
  } = deps;

  const parseBody = express.json({ limit: MAX_BODY_BYTES, type: () => true });

  function validateMac(req, res, next) {
    const mac = String(req.params.mac || '');
    if (!MAC_ADDRESS_RE.test(mac)) {
      res.status(400).json({ error: 'invalid mac address' });
      return;
    }
    req.macKey = macKey(mac);
    next();
  }

  // ACL: the caller must be associated with the target device. We match the
  // requested MAC against the caller's associated devices by normalised key
  // (separator-insensitive) and resolve `req.deviceMac` to the *actual stored*
  // form, so downstream lookups (Device row, live session key) match regardless
  // of whether the agent registered with `:` or `-`. A device the caller is not
  // associated with is reported exactly like "no session" (no enumeration).
  async function requireDeviceAssociation(req, res, next) {
    let macs;
    try {
      macs = await listUserDeviceMacs(req.authUser);
    } catch {
      res.status(500).json({ error: 'internal error' });
      return;
    }
    const match = (macs || []).find((m) => macKey(m) === req.macKey);
    if (!match) {
      res.status(404).json({ error: 'no active session for mac' });
      return;
    }
    req.deviceMac = match;
    next();
  }

  // Enqueue a command, await the terminal worker's result, and relay it. A wait
  // failure (worker down or slow) surfaces as 504. When `log` is provided, the
  // command is audit-logged (who/what/when + resulting status); a logging
  // failure never fails the command.
  async function dispatch(res, payload, waitMs, log = null) {
    let status;
    let body;
    try {
      const result = await sendCommand(payload, { waitMs });
      ({ status, body } = result);
    } catch {
      status = 504;
      body = { error: 'terminal command timed out or terminal API unavailable' };
    }
    if (log) {
      try {
        await recordCommandLog({ ...log, status });
      } catch {
        // audit-log failures must not fail the command
      }
    }
    res.status(status).json(body);
  }

  // GET /terminal/sessions — only the caller's associated devices.
  app.get('/terminal/sessions', async (req, res) => {
    let allowed;
    try {
      allowed = new Set((await listUserDeviceMacs(req.authUser)).map(macKey));
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
    const sessions = (result.body.sessions || []).filter((s) => allowed.has(macKey(s.mac)));
    res.status(200).json({ sessions });
  });

  // POST /terminal/sessions/:mac — set the device's alias and/or group.
  app.post('/terminal/sessions/:mac', validateMac, requireDeviceAssociation, parseBody, async (req, res) => {
    const body = req.body || {};
    const hasAlias = Object.prototype.hasOwnProperty.call(body, 'alias');
    const hasGroup = Object.prototype.hasOwnProperty.call(body, 'group');
    if (!hasAlias && !hasGroup) {
      res.status(400).json({ error: 'alias or group is required' });
      return;
    }

    const payload = { type: 'setMeta', mac: req.deviceMac };
    if (hasAlias) {
      if (body.alias !== null && typeof body.alias !== 'string') {
        res.status(400).json({ error: 'alias must be a string or null' });
        return;
      }
      payload.alias = body.alias;
    }
    if (hasGroup) {
      if (body.group !== null && typeof body.group !== 'string') {
        res.status(400).json({ error: 'group must be a string or null' });
        return;
      }
      payload.group = body.group;
    }

    await dispatch(res, payload, DEFAULT_WAIT_MS);
  });

  // `mode` is 'linux' (Linux shell command, run via `linux execute-command`) or
  // 'ela' (a raw ELA agent command such as `linux gdbserver ...`). The route
  // path carries it, so the client picks the interpretation explicitly.
  function makeExecHandler(mode) {
    return async (req, res) => {
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
      await dispatch(
        res,
        { type: 'exec', mode, mac: req.deviceMac, command, timeoutMs },
        waitMs,
        { username: req.authUser, macAddress: req.deviceMac, commandType: `${mode}-exec`, command },
      );
    };
  }

  function makeSpawnHandler(mode) {
    return async (req, res) => {
      const body = req.body || {};
      const command = typeof body.command === 'string' ? body.command : '';
      if (!command.trim()) {
        res.status(400).json({ error: 'command is required' });
        return;
      }

      await dispatch(
        res,
        { type: 'spawn', mode, mac: req.deviceMac, command },
        DEFAULT_WAIT_MS,
        { username: req.authUser, macAddress: req.deviceMac, commandType: `${mode}-spawn`, command },
      );
    };
  }

  // Linux shell command vs raw ELA agent command, for both exec and spawn.
  app.post('/terminal/:mac/linux/exec', validateMac, requireDeviceAssociation, parseBody, makeExecHandler('linux'));
  app.post('/terminal/:mac/ela/exec', validateMac, requireDeviceAssociation, parseBody, makeExecHandler('ela'));
  app.post('/terminal/:mac/linux/spawn', validateMac, requireDeviceAssociation, parseBody, makeSpawnHandler('linux'));
  app.post('/terminal/:mac/ela/spawn', validateMac, requireDeviceAssociation, parseBody, makeSpawnHandler('ela'));

  app.get('/terminal/:mac/spawn', validateMac, requireDeviceAssociation, async (req, res) => {
    await dispatch(res, { type: 'listSpawns', mac: req.deviceMac }, DEFAULT_WAIT_MS);
  });

  app.delete('/terminal/:mac/spawn/:pid', validateMac, requireDeviceAssociation, async (req, res) => {
    const pid = Number(req.params.pid);
    if (!Number.isInteger(pid) || pid <= 0) {
      res.status(400).json({ error: 'invalid pid' });
      return;
    }
    await dispatch(
      res,
      { type: 'killSpawn', mac: req.deviceMac, pid },
      DEFAULT_WAIT_MS,
      { username: req.authUser, macAddress: req.deviceMac, commandType: 'kill', command: `kill ${pid}` },
    );
  });
}

module.exports = registerTerminalRoutes;
module.exports.MAC_ADDRESS_RE = MAC_ADDRESS_RE;
module.exports.MAX_EXEC_TIMEOUT_MS = MAX_EXEC_TIMEOUT_MS;
