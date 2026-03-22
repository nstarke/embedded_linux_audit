// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

/**
 * Factory that returns a GDB session manager.
 *
 * Sessions are keyed by 32-char hex strings.  Each session tracks the 'in'
 * (agent/gdbserver) and 'out' (gdb-multiarch) WebSocket connections.
 */
function createSessionManager() {
  const sessions = new Map();

  function getOrCreate(key) {
    if (!sessions.has(key)) {
      sessions.set(key, { in: null, out: null });
    }
    return sessions.get(key);
  }

  function relay(dst, data) {
    if (dst && dst.readyState === dst.OPEN) {
      try {
        dst.send(data);
      } catch (err) {
        process.stderr.write(`gdb relay error: ${err.message}\n`);
      }
    }
  }

  function purge(key) {
    const s = sessions.get(key);
    if (!s) return;
    if (s.in)  { try { s.in.close();  } catch {} }
    if (s.out) { try { s.out.close(); } catch {} }
    sessions.delete(key);
  }

  function keys() {
    return sessions.keys();
  }

  return { sessions, getOrCreate, relay, purge, keys };
}

module.exports = { createSessionManager };
