// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    const n = parseInt(part, 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    result = (result << 8) | n;
  }
  return result >>> 0;
}

/**
 * Parse an IPv4 address or CIDR string.
 * Strips IPv6-mapped IPv4 prefixes (::ffff:).
 * A bare IP is treated as a /32.
 * Returns { network, mask, cidr } on success, or null if the input is invalid.
 */
function parseCidr(input) {
  if (!input || typeof input !== 'string') return null;
  const raw = input.trim().replace(/^::ffff:/i, '');
  const slashIdx = raw.indexOf('/');
  const ipStr = slashIdx === -1 ? raw : raw.slice(0, slashIdx);
  const prefixStr = slashIdx === -1 ? '32' : raw.slice(slashIdx + 1);
  const prefix = parseInt(prefixStr, 10);

  if (isNaN(prefix) || prefix < 0 || prefix > 32 || String(prefix) !== prefixStr) return null;

  const ipInt = ipv4ToInt(ipStr);
  if (ipInt === null) return null;

  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const network = (ipInt & mask) >>> 0;
  return { network, mask, cidr: `${ipStr}/${prefix}` };
}

/**
 * Returns true if remoteAddress falls within any of the parsedCidrs entries.
 * Handles IPv6-mapped IPv4 addresses (::ffff:x.x.x.x).
 */
function isBlocked(remoteAddress, parsedCidrs) {
  if (!remoteAddress || !parsedCidrs || parsedCidrs.length === 0) return false;
  const raw = remoteAddress.replace(/^::ffff:/i, '');
  const ipInt = ipv4ToInt(raw);
  if (ipInt === null) return false;
  return parsedCidrs.some(({ network, mask }) => (ipInt & mask) >>> 0 === network);
}

module.exports = { parseCidr, isBlocked };
