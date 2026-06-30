// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const crypto = require('crypto');

/*
 * Keys are read from the database on every check (no startup cache), so newly
 * created or revoked keys take effect immediately without restarting a service.
 * The module holds only the loader + enforcement flag configured by init().
 */
let defaultLoader = null; /* () => Promise<Array<{keyHash, username}>> */
let defaultEnforced = false;

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

/**
 * Configure the default auth instance.
 *
 * @param {boolean}  [enforced=false]  When true, requests are rejected even if
 *   no keys exist (hard lockdown, e.g. --validate-key). When false, auth is
 *   "dynamic": enforced as soon as any key exists for the scope, open otherwise.
 * @param {Function} loadKeys  Async function returning the current array of
 *   `{ keyHash, username }` for this service's scope. Invoked on every check.
 * @returns {Promise<boolean>} Always true (key state is now dynamic; there is
 *   no startup gate on key count).
 */
async function init(enforced, loadKeys) {
  defaultEnforced = Boolean(enforced);
  defaultLoader = loadKeys;
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
 * Match an Authorization header value against an explicit list of token hashes.
 * Always iterates every entry (no short-circuit) to avoid timing oracles.
 * Stateless — the caller supplies the key set.
 *
 * @returns {string|null} The authenticated username when a key matches, else null.
 */
function matchBearer(authHeader, keyHashes) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;

  const token = authHeader.slice(7);
  const tokenHash = crypto.createHash('sha256').update(token, 'utf8').digest('hex');
  let matchedUser = null;
  for (const entry of keyHashes) {
    if (constantTimeEqual(tokenHash, entry.keyHash)) matchedUser = entry.username; /* no break — constant time */
  }
  return matchedUser;
}

/**
 * Resolve an Authorization header against the current database key set.
 *
 * Reads keys via the loader on every call (per-request DB read). Enforcement is
 * dynamic: when keys exist for the scope a valid token is required; when no keys
 * exist (and not hard-enforced) the request is allowed without a user.
 *
 * @param {string|undefined} authHeader
 * @param {Function} [loader]   Defaults to the one set by init() (a specific
 *   scope's loader can be passed, e.g. for the gdb bridge's two directions).
 * @param {boolean}  [enforced] Defaults to the flag set by init().
 * @returns {Promise<string|true|false>} username on match; true when open
 *   (no keys, not enforced); false on rejection.
 */
async function resolveBearer(authHeader, loader = defaultLoader, enforced = defaultEnforced) {
  if (!loader) return true; /* uninitialised (e.g. tests) -> open */
  const keys = (await loader()) || [];
  if (keys.length === 0 && !enforced) return true;
  const matched = matchBearer(authHeader, keys);
  return matched !== null ? matched : false;
}

/**
 * Async back-compat wrapper over resolveBearer using the default loader.
 * @returns {Promise<string|true|false>}
 */
async function checkBearer(authHeader) {
  return resolveBearer(authHeader);
}

/* -------------------------------------------------------------------------
 * Express middleware
 * ---------------------------------------------------------------------- */

/**
 * Express (5) async middleware. Rejects requests without a valid bearer token
 * with HTTP 401; passes through when auth is open. On success, attaches the
 * authenticated identity:
 *   - req.authUser    the matched username (when a specific user matched)
 *   - req.authKeyHash the SHA-256 hex of the presented token
 * A loader/DB error is treated as a rejection (fail closed) rather than an
 * unhandled rejection.
 */
async function middleware(req, res, next) {
  let result;
  try {
    result = await resolveBearer(req.headers['authorization']);
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  if (!result) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    req.authKeyHash = crypto.createHash('sha256').update(token, 'utf8').digest('hex');
  }
  if (typeof result === 'string') {
    req.authUser = result;
  }
  return next();
}

module.exports = { init, checkBearer, resolveBearer, matchBearer, middleware };
