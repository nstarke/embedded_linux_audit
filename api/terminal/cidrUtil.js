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

const PRIVATE_IPV4_CIDRS = [
  { network: 0x7f000000, mask: 0xff000000 }, // 127.0.0.0/8
  { network: 0x0a000000, mask: 0xff000000 }, // 10.0.0.0/8
  { network: 0xac100000, mask: 0xfff00000 }, // 172.16.0.0/12
  { network: 0xc0a80000, mask: 0xffff0000 }, // 192.168.0.0/16
];

/**
 * Returns true if the given IP address is a private/loopback address.
 * Handles IPv4, IPv6-mapped IPv4 (::ffff:x.x.x.x), IPv6 loopback (::1),
 * and IPv6 unique-local (fc00::/7).
 */
function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const raw = ip.trim().replace(/^::ffff:/i, '');
  if (raw === '::1') return true;
  if (/^f[cd][0-9a-f]{0,2}:/i.test(raw)) return true; // fc00::/7
  const ipInt = ipv4ToInt(raw);
  if (ipInt === null) return false;
  return PRIVATE_IPV4_CIDRS.some(({ network, mask }) => (ipInt & mask) >>> 0 === network);
}

/**
 * If remoteAddress is a private IP, returns the first non-empty value from
 * X-Forwarded-For or X-Real-IP headers; otherwise returns remoteAddress.
 *
 * @param {string|null} remoteAddress  The raw socket remote address.
 * @param {object} headers             The HTTP request headers object.
 * @returns {string|null}
 */
function resolveProxiedAddress(remoteAddress, headers) {
  if (!isPrivateIp(remoteAddress)) return remoteAddress;
  const forwarded = headers && headers['x-forwarded-for'];
  if (forwarded) {
    const first = String(forwarded).split(',')[0].trim();
    if (first) return first;
  }
  const realIp = headers && headers['x-real-ip'];
  if (realIp) {
    const trimmed = String(realIp).trim();
    if (trimmed) return trimmed;
  }
  return remoteAddress;
}

module.exports = { parseCidr, isBlocked, isPrivateIp, resolveProxiedAddress };
