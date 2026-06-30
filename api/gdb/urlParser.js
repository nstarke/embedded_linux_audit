// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const HEX32_RE = /^[0-9a-f]{32}$/;
// Path plus an optional query string; the agent (in) side appends ?mac=<mac>
// so the bridge can record which device the session belongs to.
const GDB_URL_RE = /^\/gdb\/(in|out)\/([0-9a-f]{32})(?:\?(.*))?$/;
const MAC_RE = /^[0-9a-fA-F:.-]{1,64}$/;

/**
 * Parse a GDB tunnel WebSocket URL path.
 * Returns { direction: 'in'|'out', hexkey: string, mac: string|null } or null
 * if the path is invalid. mac is the device MAC carried by the agent (in) side
 * (`?mac=<mac>`), or null when absent or malformed.
 */
function parseGdbUrl(url) {
  const m = (url || '').match(GDB_URL_RE);
  if (!m) return null;
  return { direction: m[1], hexkey: m[2], mac: parseMac(m[3]) };
}

function parseMac(query) {
  if (!query) return null;
  for (const part of query.split('&')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq) !== 'mac') continue;
    let value;
    try {
      value = decodeURIComponent(part.slice(eq + 1));
    } catch {
      return null;
    }
    return MAC_RE.test(value) ? value.toLowerCase() : null;
  }
  return null;
}

/**
 * Return true if key is exactly 32 lowercase hex characters.
 */
function isValidHexKey(key) {
  return typeof key === 'string' && HEX32_RE.test(key);
}

module.exports = { parseGdbUrl, isValidHexKey };
