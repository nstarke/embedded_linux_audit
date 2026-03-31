// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const crypto = require('crypto');

let validKeyHashes = []; /* array of { keyHash, username } */
let authRequired = false;

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

/**
 * Load bearer token hashes from the database and configure enforcement.
 *
 * @param {boolean}  [enforced=false]  Pass true when --validate-key is set.
 *   - enforced=false: auth is not required regardless of keys in the database.
 *   - enforced=true:  auth is required; returns false (caller should exit)
 *                     if no keys are found in the database.
 * @param {Function} loadKeys  Async function that returns an array of
 *                             SHA-256 hex hashes of valid bearer tokens.
 * @returns {Promise<boolean>} true on success, false when enforced but no
 *                             keys are configured.
 */
async function init(enforced, loadKeys) {
  enforced = Boolean(enforced);

  validKeyHashes = await loadKeys();

  if (enforced && validKeyHashes.length === 0) {
    authRequired = false;
    return false; /* caller must warn and exit */
  }

  authRequired = enforced;
  return true;
}

/* -------------------------------------------------------------------------
 * Constant-time comparison
 * ---------------------------------------------------------------------- */

/**
 * Constant-time comparison of two strings.
 * Pads both to the same length before comparing so the result does not
 * leak the length of either value through timing.
 */
function constantTimeEqual(a, b) {
  const maxLen = Math.max(a.length, b.length, 1);
  const aBuf = Buffer.alloc(maxLen, 0);
  const bBuf = Buffer.alloc(maxLen, 0);
  Buffer.from(a, 'utf8').copy(aBuf, 0, 0, Math.min(a.length, maxLen));
  Buffer.from(b, 'utf8').copy(bBuf, 0, 0, Math.min(b.length, maxLen));
  return crypto.timingSafeEqual(aBuf, bBuf);
}

/* -------------------------------------------------------------------------
 * Token validation
 * ---------------------------------------------------------------------- */

/**
 * Check an Authorization header value against all loaded token hashes.
 * Always iterates every entry (no short-circuit) to avoid timing oracles.
 *
 * @param {string|undefined} authHeader  Value of the Authorization header.
 * @returns {string|true|false}  The authenticated username when a key matches;
 *   true when auth is not required (no specific user); false on rejection.
 */
function checkBearer(authHeader) {
  if (!authRequired) return true;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;

  const token = authHeader.slice(7);
  const tokenHash = crypto.createHash('sha256').update(token, 'utf8').digest('hex');
  let matchedUser = null;
  for (const entry of validKeyHashes) {
    if (constantTimeEqual(tokenHash, entry.keyHash)) matchedUser = entry.username; /* no break — constant time */
  }
  return matchedUser !== null ? matchedUser : false;
}

/* -------------------------------------------------------------------------
 * Express middleware
 * ---------------------------------------------------------------------- */

/**
 * Express middleware that rejects requests without a valid bearer token
 * with HTTP 401.  Passes through when auth is not required.
 */
function middleware(req, res, next) {
  if (checkBearer(req.headers['authorization'])) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

module.exports = { init, checkBearer, middleware };
