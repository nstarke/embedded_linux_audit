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

// Inverse of a POSIX-sh single-quoted word: resolve `'...'` segments and `\c`
// escapes back to the literal string. Recovers a value written as
// `'` + shSingleQuote(v) + `'` (see buildWrapperHeader), used when rebuilding a
// launcher from an existing one.
function shUnquote(s) {
  let out = '';
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === "'") {
      i += 1;
      while (i < s.length && s[i] !== "'") { out += s[i]; i += 1; }
      i += 1; // skip the closing quote
    } else if (c === '\\') {
      i += 1;
      if (i < s.length) { out += s[i]; i += 1; }
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

/**
 * Derive the HTTP(S) base URL for command output uploads from the terminal-API
 * URL baked into the launcher. Command outputs are POSTed to the agent API's
 * `/<mac>/upload/<type>` endpoint (the agent appends that path itself), which
 * makes them retrievable through the client `/uploads` routes.
 *
 * The terminal API and the agent API sit behind the same host:port (see
 * nginx/ela.conf), so we only need to translate the scheme: the WebSocket
 * `wss://`/`ws://` schemes map to `https://`/`http://`. A URL that already uses
 * an HTTP scheme is kept as-is; a bare `host[:port]` defaults to plaintext HTTP.
 * An empty/missing URL yields '' (no output routing).
 * @param {string} serverUrl
 * @returns {string}
 */
function deriveOutputHttpUrl(serverUrl) {
  const url = String(serverUrl == null ? '' : serverUrl).trim();
  if (!url) return '';
  if (url.startsWith('wss://')) return `https://${url.slice('wss://'.length)}`;
  if (url.startsWith('ws://')) return `http://${url.slice('ws://'.length)}`;
  if (url.startsWith('https://') || url.startsWith('http://')) return url;
  return `http://${url}`;
}

/**
 * Parse the launcher header text (everything before the payload marker) back
 * into the values it was built with. Returns null if no token line is found.
 * @param {string} text
 * @returns {{token:string, serverUrl:string, insecure:boolean}|null}
 */
function parseLauncherHeader(text) {
  const grab = (name) => {
    const m = String(text).match(new RegExp(`^${name}=(.*)$`, 'm'));
    return m ? shUnquote(m[1].trim()) : null;
  };
  const token = grab('ELA_TOKEN');
  if (!token) return null;
  return {
    token,
    serverUrl: grab('ELA_REMOTE') || '',
    insecure: grab('ELA_INSECURE') === 'true',
  };
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
 *   2b. exports ELA_OUTPUT_HTTP (derived from the terminal-API URL) so every
 *      command's output is uploaded to the agent API and retrievable via the
 *      client `/uploads` routes,
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
  // The agent validates that ELA_OUTPUT_HTTP holds an http:// URL and
  // ELA_OUTPUT_HTTPS holds an https:// one — a mismatched scheme is rejected and
  // the agent prints usage instead of running. Pick the variable by scheme.
  const outputUrl = deriveOutputHttpUrl(serverUrl);
  const qOutputUrl = shSingleQuote(outputUrl);
  const outputVar = outputUrl.startsWith('https://') ? 'ELA_OUTPUT_HTTPS' : 'ELA_OUTPUT_HTTP';
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
ELA_OUTPUT_URL='${qOutputUrl}'
ELA_INSECURE='${qInsecure}'

export ELA_API_KEY="$ELA_TOKEN"

# Emit machine-readable JSON from every command so callers (the terminal API's
# exec endpoints, the /uploads records) can parse the output directly rather
# than scraping text. A caller may still override it per-invocation.
export ELA_OUTPUT_FORMAT="\${ELA_OUTPUT_FORMAT:-json}"

# Route every command's output (dmesg, netstat, exec, …) to the agent API's
# upload endpoint so results are retrievable via the client /uploads routes.
# The agent requires an http:// URL in ELA_OUTPUT_HTTP and an https:// URL in
# ELA_OUTPUT_HTTPS (a scheme mismatch makes it print usage and exit), so the
# right variable is chosen by scheme at build time. The agent appends
# /<mac>/upload/<type> itself; this applies to both a bare phone-home run and
# \`launcher linux <cmd>\` invocations.
if [ -n "$ELA_OUTPUT_URL" ]; then
    export ${outputVar}="$ELA_OUTPUT_URL"
fi

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

module.exports = {
  PAYLOAD_MARKER,
  shSingleQuote,
  shUnquote,
  deriveOutputHttpUrl,
  parseLauncherHeader,
  buildWrapperHeader,
  assembleWrapper,
};
