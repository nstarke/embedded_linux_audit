// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const HEX32_RE = /^[0-9a-f]{32}$/;
const GDB_URL_RE = /^\/gdb\/(in|out)\/([0-9a-f]{32})$/;

/**
 * Parse a GDB tunnel WebSocket URL path.
 * Returns { direction: 'in'|'out', hexkey: string } or null if invalid.
 */
function parseGdbUrl(url) {
  const m = (url || '').match(GDB_URL_RE);
  if (!m) return null;
  return { direction: m[1], hexkey: m[2] };
}

/**
 * Return true if key is exactly 32 lowercase hex characters.
 */
function isValidHexKey(key) {
  return typeof key === 'string' && HEX32_RE.test(key);
}

module.exports = { parseGdbUrl, isValidHexKey };
