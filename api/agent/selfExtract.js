// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const crypto = require('crypto');

// Marker line separating the POSIX-sh launcher header from the appended binary
// payload. It appears exactly once (in the header); the extractor stops at the
// first match, so a coincidental occurrence inside the binary is harmless.
const PAYLOAD_MARKER = '__ELA_PAYLOAD__';

// Quote an arbitrary string for safe inclusion inside a single-quoted POSIX-sh
// literal: close the quote, emit an escaped quote, reopen. Result is always
// wrapped in single quotes by the caller's template.
function shSingleQuote(value) {
  return String(value == null ? '' : value).replace(/'/g, "'\\''");
}

/**
 * Build the POSIX-sh launcher header that precedes the embedded agent binary.
 *
 * At runtime the launcher:
 *   1. exports ELA_API_KEY=<token> (the agent's highest-priority runtime token
 *      source after --api-key),
 *   2. seeds /tmp/.ela.conf with `remote=<serverUrl>` on first run only, so a
 *      bare invocation auto-connects to the terminal API — reproducing the old
 *      compile-time ELA_EMBEDDED_SERVER_URL behavior, including the duality
 *      (`launcher` phones home; `launcher linux dmesg` runs locally),
 *   3. extracts the appended binary to a stable per-payload cache path and
 *      execs it, forwarding all arguments.
 *
 * The extraction uses `awk` to find the marker's line number and `tail -n +N`
 * to copy the payload byte-for-byte (safe for binary content). Only `sh`,
 * `awk`, `tail` and `chmod` are required — all present in busybox.
 *
 * @param {object} opts
 * @param {string} opts.token        Agent bearer token (exported as ELA_API_KEY).
 * @param {string} [opts.serverUrl]  Terminal-API WS URL; empty ⇒ no phone-home seeding.
 * @param {boolean} [opts.insecure]  Seed `insecure=true` (skip TLS verification).
 * @param {string} opts.cacheKey     Opaque id for the extracted-binary cache path.
 * @returns {string} The launcher header, ending with the marker line + newline.
 */
function buildWrapperHeader({ token, serverUrl = '', insecure = false, cacheKey }) {
  if (!token) throw new Error('buildWrapperHeader: token is required');
  if (!cacheKey) throw new Error('buildWrapperHeader: cacheKey is required');

  const qToken = shSingleQuote(token);
  const qRemote = shSingleQuote(serverUrl);
  const qInsecure = insecure ? 'true' : 'false';
  const qCache = shSingleQuote(`.ela-agent-${cacheKey}`);

  return `#!/bin/sh
# Self-extracting ELA agent launcher — sets the API token and, on a bare run,
# connects to the terminal-API URL, then runs the embedded agent binary.
# Generated file; do not edit. The token below is a secret: treat this file like
# a credential.
set -eu

ELA_TOKEN='${qToken}'
ELA_REMOTE='${qRemote}'
ELA_INSECURE='${qInsecure}'

export ELA_API_KEY="$ELA_TOKEN"

# Extract the appended binary to a stable cache path (the agent may daemonize,
# so the file must persist) and exec it.
_ela_bin="\${TMPDIR:-/tmp}/${qCache}"
if [ ! -x "$_ela_bin" ]; then
    _ela_tmp="$_ela_bin.$$"
    _ela_line=$(awk '/^${PAYLOAD_MARKER}$/ { print NR + 1; exit }' "$0")
    tail -n +"$_ela_line" "$0" > "$_ela_tmp"
    chmod 0755 "$_ela_tmp"
    mv "$_ela_tmp" "$_ela_bin"
fi

# With NO arguments and a baked-in URL, phone home to the terminal API
# (\`--remote\` triggers the connect/daemonize path) — reproducing an embedded
# server URL. With any arguments, run them locally (e.g. \`launcher linux dmesg\`);
# --remote cannot be combined with a command, so we only add it on a bare run.
if [ "$#" -eq 0 ] && [ -n "$ELA_REMOTE" ]; then
    if [ "$ELA_INSECURE" = "true" ]; then
        set -- --insecure --remote "$ELA_REMOTE"
    else
        set -- --remote "$ELA_REMOTE"
    fi
fi

exec "$_ela_bin" "$@"
# Should never be reached; guards against the shell falling through into the
# binary payload if exec fails.
exit 1
${PAYLOAD_MARKER}
`;
}

/**
 * Assemble a complete self-extracting launcher: the sh header followed by the
 * raw generic binary bytes.
 *
 * @param {Buffer} genericBinary  Raw (unembedded) agent binary for one ISA.
 * @param {object} opts
 * @param {string} opts.token
 * @param {string} [opts.serverUrl]
 * @param {boolean} [opts.insecure]
 * @param {string} [opts.isa]      ISA label, used only to make the cache path readable.
 * @returns {Buffer}
 */
function assembleWrapper(genericBinary, { token, serverUrl = '', insecure = false, isa = 'agent' } = {}) {
  if (!Buffer.isBuffer(genericBinary)) {
    throw new Error('assembleWrapper: genericBinary must be a Buffer');
  }
  // Cache key ties the extracted file to this exact payload, so a rebuilt or
  // different-ISA binary never reuses a stale cached copy.
  const digest = crypto.createHash('sha256').update(genericBinary).digest('hex').slice(0, 16);
  const safeIsa = String(isa).replace(/[^A-Za-z0-9._-]/g, '');
  const header = buildWrapperHeader({
    token,
    serverUrl,
    insecure,
    cacheKey: `${safeIsa}-${digest}`,
  });
  return Buffer.concat([Buffer.from(header, 'utf8'), genericBinary]);
}

module.exports = { PAYLOAD_MARKER, shSingleQuote, buildWrapperHeader, assembleWrapper };
