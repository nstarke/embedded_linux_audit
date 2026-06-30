// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { runExec } = require('./execCommand');

const MAC_ADDRESS_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const MAX_BODY_BYTES = 1024 * 1024;

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function sendText(res, statusCode, body) {
  res.writeHead(statusCode, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(body);
}

function readJsonBody(req, { limit = MAX_BODY_BYTES } = {}) {
  return new Promise((resolve, reject) => {
    let raw = '';
    let aborted = false;
    req.on('data', (chunk) => {
      if (aborted) {
        return;
      }
      raw += chunk;
      if (raw.length > limit) {
        aborted = true;
        reject(Object.assign(new Error('payload too large'), { code: 'PAYLOAD_TOO_LARGE' }));
      }
    });
    req.on('end', () => {
      if (aborted) {
        return;
      }
      if (!raw.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(Object.assign(new Error('invalid JSON body'), { code: 'INVALID_JSON' }));
      }
    });
    req.on('error', (err) => {
      if (!aborted) {
        reject(err);
      }
    });
  });
}

function createTerminalHttpHandler(deps = {}) {
  const {
    sessionRegistry = null,
    auth = null,
    blockedCidrs = [],
    isBlocked = () => false,
    resolveRemoteAddress = (req) => (req.socket && req.socket.remoteAddress) || '',
    runExecImpl = runExec,
  } = deps;

  function isAuthorized(req) {
    if (!auth || typeof auth.checkBearer !== 'function') {
      return true;
    }
    return Boolean(auth.checkBearer(req.headers && req.headers.authorization));
  }

  function listSessions(res) {
    const sessions = sessionRegistry.entries().map(([mac, entry]) => ({
      mac,
      alias: entry.alias || null,
      group: entry.group || null,
      remoteAddress: entry.remoteAddress || null,
      connectedAt: entry.connectedAt || null,
      lastHeartbeat: entry.lastHeartbeat || null,
    }));
    sendJson(res, 200, sessions);
  }

  async function execOnSession(req, res, mac) {
    let body;
    try {
      body = await readJsonBody(req);
    } catch (err) {
      sendJson(res, err.code === 'PAYLOAD_TOO_LARGE' ? 413 : 400, { error: err.message });
      return;
    }

    const command = body && typeof body.command === 'string' ? body.command : '';
    if (!command.trim()) {
      sendJson(res, 400, { error: 'command is required' });
      return;
    }

    let timeoutMs;
    if (body.timeoutMs !== undefined && body.timeoutMs !== null) {
      timeoutMs = Number(body.timeoutMs);
      if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
        sendJson(res, 400, { error: 'timeoutMs must be a positive number' });
        return;
      }
    }

    const entry = sessionRegistry.getSession(mac);
    if (!entry) {
      sendJson(res, 404, { error: 'no active session for mac' });
      return;
    }

    try {
      const result = await runExecImpl({ entry, mac, command, timeoutMs });
      sendJson(res, 200, { ok: true, output: result.output, durationMs: result.durationMs });
    } catch (err) {
      if (err.code === 'TIMEOUT') {
        sendJson(res, 504, {
          ok: false,
          error: 'exec timed out',
          output: err.output || '',
          durationMs: err.durationMs,
        });
        return;
      }
      if (err.code === 'NOT_CONNECTED') {
        sendJson(res, 404, { error: 'no active session for mac' });
        return;
      }
      sendJson(res, 500, { error: 'exec failed' });
    }
  }

  return function terminalHttpHandler(req, res) {
    const url = req.url || '';
    const method = req.method;
    const path = url.split('?')[0];

    if (method === 'GET' && path === '/terminal/healthcheck') {
      sendText(res, 200, 'ok');
      return;
    }

    // The session/exec routes need access to live session state. When the
    // handler is constructed without a registry (e.g. in isolation tests) they
    // simply fall through to the 404 below.
    if (sessionRegistry) {
      if (isBlocked(resolveRemoteAddress(req), blockedCidrs)) {
        sendText(res, 403, 'Forbidden');
        return;
      }

      if (method === 'GET' && path === '/terminal/sessions') {
        if (!isAuthorized(req)) {
          sendJson(res, 401, { error: 'Unauthorized' });
          return;
        }
        listSessions(res);
        return;
      }

      const execMatch = path.match(/^\/terminal\/([^/]+)\/exec$/);
      if (execMatch && method === 'POST') {
        if (!isAuthorized(req)) {
          sendJson(res, 401, { error: 'Unauthorized' });
          return;
        }
        const mac = decodeURIComponent(execMatch[1]).toLowerCase();
        if (!MAC_ADDRESS_RE.test(mac)) {
          sendJson(res, 400, { error: 'invalid mac address' });
          return;
        }
        void execOnSession(req, res, mac);
        return;
      }
    }

    sendText(res, 404, 'Not Found');
  };
}

module.exports = {
  createTerminalHttpHandler,
};
