// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

// Shared bounds for the fuzz case ring the agent API holds per streaming
// connection (see api/agent/wlanFuzzWebSocket.js). Kept here, free of any
// websocket/db dependency, so the client API can validate the setting without
// pulling in `ws` and the agent API can size the ring without pulling in the
// settings store.
//
// MAX bounds worst-case memory: a case line is capped at ~2 KB by the agent
// (CASE_MAX_BYTES), so a full ring costs ~2 MB per live fuzz.
const DEFAULT_RING_SIZE = 10;
const MAX_RING_SIZE = 1000;

// Coerce a stored/streamed value to a usable ring size. Anything malformed or
// out of range falls back rather than throwing: crash capture matters more than
// the knob.
function normalizeRingSize(value, fallback = DEFAULT_RING_SIZE) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) return fallback;
  return Math.min(n, MAX_RING_SIZE);
}

module.exports = {
  DEFAULT_RING_SIZE,
  MAX_RING_SIZE,
  normalizeRingSize,
};
