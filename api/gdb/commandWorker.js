// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

// Process one query received over the `ela-gdb-commands` queue (produced by the
// client API) against the GDB bridge's in-memory session map. The return value
// becomes the BullMQ job's result, which the client API awaits and relays.
//
// Every outcome is returned as `{ status, body }` (an HTTP status + JSON body)
// so the client route is a thin proxy. The client API is the ACL boundary
// (device association): this worker returns every active session and the client
// route filters them to the caller's associated devices.

// Serialize one live session for the wire. The WebSocket handles held in the
// session (`in`/`out`) are not serializable and must never be sent; only the
// attach handle (hexkey), the device MAC, and connection state are exposed.
function serializeSession(hexkey, session) {
  return {
    hexkey,
    mac: session.deviceMac,
    // Whether an operator (gdb) is currently attached to the out side.
    operatorConnected: Boolean(session.out),
  };
}

// List active gdbserver sessions: those where the agent (in) side is connected
// and has declared a device MAC, so the session is attributable to a device.
// A device may have MANY concurrent sessions (distinct hexkeys) — each is its
// own entry, so the caller sees every gdbserver instance on that MAC.
function listSessions(sessions) {
  const out = [];
  for (const [hexkey, session] of sessions.entries()) {
    if (session && session.in && session.deviceMac) {
      out.push(serializeSession(hexkey, session));
    }
  }
  return { status: 200, body: { sessions: out } };
}

/**
 * Dispatch one queued GDB query. Returns `{ status, body }`.
 *
 * @param {object} opts
 * @param {object} opts.job       BullMQ job; job.data = { type, ... }.
 * @param {Map} opts.sessions     The GDB bridge's live session map
 *                                (hexkey -> { in, out, deviceMac }).
 */
async function processGdbCommand({ job, sessions }) {
  const data = (job && job.data) || {};
  switch (data.type) {
    case 'sessions':
      return listSessions(sessions);
    default:
      return { status: 400, body: { error: `unknown command type: ${String(data.type)}` } };
  }
}

module.exports = { processGdbCommand, serializeSession, listSessions };
