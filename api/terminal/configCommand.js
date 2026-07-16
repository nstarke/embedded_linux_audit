// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const crypto = require('crypto');

// Read a device's effective settings over the session's control channel.
//
// This deliberately does NOT go through the REPL. Reading a setting used to
// mean running `set` as an exec and scraping `ELA_API_URL current=...` out of
// the session output, which serializes behind whatever command is already
// running on that device — a whole-rootfs `remote-copy` holds it for up to an
// hour, so the read timed out and callers misreported it as "the device has no
// ELA_API_URL". The agent answers `config.get` from its WebSocket parent
// process (see agent/net/ws_config_util.h), which is never blocked by a busy
// REPL, so this is safe to call at any time.
//
// Replies are correlated by request id off `entry.configWaiters`, which
// server.js populates when a `config.value` frame arrives. That map is created
// lazily so a session entry that never reads config carries no extra state.

const DEFAULT_CONFIG_TIMEOUT_MS = 10000;

// The agent refuses anything outside its own readable-key policy, so this list
// is a courtesy check that fails fast rather than the security boundary. The
// boundary is ela_ws_config_key_is_readable() on the device: notably it never
// serves ELA_API_KEY, and neither should any caller ask for it.
const READABLE_KEYS = new Set([
  'ELA_API_URL',
  'ELA_OUTPUT_HTTP',
  'ELA_OUTPUT_FORMAT',
  'ELA_API_INSECURE',
  'ELA_OUTPUT_INSECURE',
]);

function waitersFor(entry) {
  if (!entry.configWaiters) {
    entry.configWaiters = new Map();
  }
  return entry.configWaiters;
}

/**
 * Resolve a pending config.get. Called by the terminal server when a
 * `config.value` frame arrives. Returns true when the id matched a waiter.
 *
 * @param {object} entry  Live session entry.
 * @param {object} msg    Parsed `{_type:'config.value', id, values}` frame.
 */
function deliverConfigValue(entry, msg) {
  if (!entry || !entry.configWaiters || !msg || typeof msg.id !== 'string') {
    return false;
  }
  const waiter = entry.configWaiters.get(msg.id);
  if (!waiter) {
    return false;
  }
  entry.configWaiters.delete(msg.id);
  waiter.resolve(msg.values && typeof msg.values === 'object' ? msg.values : {});
  return true;
}

/**
 * Ask a device for its effective settings.
 *
 * Resolves with a plain `{ KEY: value }` object; a key the device does not have
 * set comes back as an empty string, and a key it refuses is simply absent —
 * both are answers, not failures. Rejects with an Error carrying `code`:
 *   - 'NOT_CONNECTED' when the session WebSocket is not open
 *   - 'TIMEOUT'       when the device does not answer within timeoutMs
 *   - 'SEND_FAILED'   when the request could not be written to the socket
 *
 * The distinction matters: callers must not conflate "the device answered and
 * has no ELA_API_URL" with "we never got to ask".
 */
function runConfigGet({
  entry,
  keys,
  timeoutMs = DEFAULT_CONFIG_TIMEOUT_MS,
  setTimeoutImpl = setTimeout,
  clearTimeoutImpl = clearTimeout,
  idImpl = () => crypto.randomUUID(),
} = {}) {
  return new Promise((resolve, reject) => {
    const ws = entry && entry.ws;
    if (!ws || ws.readyState !== ws.OPEN) {
      reject(Object.assign(new Error('session is not connected'), { code: 'NOT_CONNECTED' }));
      return;
    }

    const wanted = (Array.isArray(keys) ? keys : []).filter((k) => READABLE_KEYS.has(k));
    const id = idImpl();
    const waiters = waitersFor(entry);
    let timer = null;

    const settle = (fn) => (value) => {
      if (timer) {
        clearTimeoutImpl(timer);
        timer = null;
      }
      waiters.delete(id);
      fn(value);
    };
    const done = settle(resolve);
    const fail = settle(reject);

    waiters.set(id, { resolve: done });

    timer = setTimeoutImpl(() => {
      fail(Object.assign(new Error('config.get timed out'), { code: 'TIMEOUT' }));
    }, timeoutMs);

    try {
      ws.send(JSON.stringify({ _type: 'config.get', id, keys: wanted }));
    } catch (err) {
      fail(Object.assign(err, { code: 'SEND_FAILED' }));
    }
  });
}

module.exports = {
  runConfigGet,
  deliverConfigValue,
  READABLE_KEYS,
  DEFAULT_CONFIG_TIMEOUT_MS,
};
