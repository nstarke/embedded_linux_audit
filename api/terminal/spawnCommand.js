// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { formatShellExecution } = require('./listCommands');

// How long to wait for the agent to report the spawned PID before giving up.
const DEFAULT_SPAWN_TIMEOUT_MS = 15000;
// After the PID is known, how long to keep watching the session output for a
// "port <N>" line before resolving without a port.  Only used when the caller
// did not supply a port explicitly.
const DEFAULT_PORT_WAIT_MS = 2000;
// Cap captured output so a chatty process cannot exhaust memory while we scan.
const MAX_SPAWN_OUTPUT_BYTES = 64 * 1024;

// Marker echoed by the agent immediately after backgrounding the process so we
// can recover the child PID from the shell's `$!`.
const SPAWN_SENTINEL = '__ELA_SPAWN__';

// gdbserver prints "Listening on port 1234"; the SSH tunnel prints a similar
// "... port 1234" line.  Match the first such number after the sentinel.
const PORT_RE = /port\s+(\d+)/i;

// Single-quote a token so the agent's shell treats it literally, escaping any
// embedded single quotes.
function shellQuote(token) {
  return `'${String(token).replace(/'/g, "'\\''")}'`;
}

// Build the shell line sent to the agent: launch the process in the background
// and echo the sentinel plus its PID so we can capture it from the output.
function buildSpawnLine(command, args) {
  const parts = [command, ...args].map(shellQuote).join(' ');
  return `${parts} & echo ${SPAWN_SENTINEL} $!`;
}

// Launch a long-running process on an attached session and capture its PID.
//
// Unlike runExec (which waits for the prompt to return), the spawned process is
// backgrounded, so the shell returns immediately and the agent echoes
// `__ELA_SPAWN__ <pid>`.  When `port` is not supplied the output stream is then
// watched briefly for a "port <N>" line that gdbserver / the tunnel emit.
//
// Resolves with { pid, port } where `port` is the caller-supplied value when
// given, otherwise the detected port, otherwise undefined.
// Rejects with an Error carrying a `code` of:
//   - 'NOT_CONNECTED' when the session WebSocket is not open
//   - 'TIMEOUT' when no PID is reported within timeoutMs
//   - 'SEND_FAILED' when the command could not be written to the socket
function runSpawn({
  entry,
  mac, // eslint-disable-line no-unused-vars -- kept for signature parity with runExec
  command,
  args = [],
  port,
  timeoutMs = DEFAULT_SPAWN_TIMEOUT_MS,
  portWaitMs = DEFAULT_PORT_WAIT_MS,
  now = () => Date.now(),
  setTimeoutImpl = setTimeout,
  clearTimeoutImpl = clearTimeout,
} = {}) {
  return new Promise((resolve, reject) => {
    const ws = entry && entry.ws;
    if (!ws || ws.readyState !== ws.OPEN) {
      reject(Object.assign(new Error('session is not connected'), { code: 'NOT_CONNECTED' }));
      return;
    }

    const startedAt = now();
    let buffer = '';
    let pid = null;
    let detectedPort = null;
    let settled = false;
    let pidTimer = null;
    let portTimer = null;

    function cleanup() {
      if (pidTimer) {
        clearTimeoutImpl(pidTimer);
        pidTimer = null;
      }
      if (portTimer) {
        clearTimeoutImpl(portTimer);
        portTimer = null;
      }
      entry.outputListeners.delete(onOutput);
    }

    function finish() {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      const resolvedPort = port !== undefined ? port
        : (detectedPort !== null ? detectedPort : undefined);
      resolve({ pid, port: resolvedPort });
    }

    function onOutput(text) {
      if (settled) {
        return;
      }
      buffer += text;
      if (buffer.length > MAX_SPAWN_OUTPUT_BYTES) {
        buffer = buffer.slice(-MAX_SPAWN_OUTPUT_BYTES);
      }

      if (pid === null) {
        const match = buffer.match(new RegExp(`${SPAWN_SENTINEL}\\s+(\\d+)`));
        if (!match) {
          return;
        }
        pid = Number(match[1]);
        // A caller-supplied port is authoritative — no need to scan output.
        if (port !== undefined) {
          finish();
          return;
        }
        // Otherwise watch the remainder of the stream for the bound port.
        if (pidTimer) {
          clearTimeoutImpl(pidTimer);
          pidTimer = null;
        }
        buffer = buffer.slice(match.index + match[0].length);
        portTimer = setTimeoutImpl(finish, portWaitMs);
        return;
      }

      const portMatch = buffer.match(PORT_RE);
      if (portMatch) {
        detectedPort = Number(portMatch[1]);
        finish();
      }
    }

    entry.outputListeners.add(onOutput);

    pidTimer = setTimeoutImpl(() => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(Object.assign(new Error('spawn timed out'), {
        code: 'TIMEOUT',
        durationMs: now() - startedAt,
      }));
    }, timeoutMs);

    try {
      ws.send(`${formatShellExecution(buildSpawnLine(command, args))}\n`);
    } catch (err) {
      if (!settled) {
        settled = true;
        cleanup();
        reject(Object.assign(err, { code: 'SEND_FAILED' }));
      }
    }
  });
}

module.exports = {
  runSpawn,
  buildSpawnLine,
  shellQuote,
  SPAWN_SENTINEL,
  DEFAULT_SPAWN_TIMEOUT_MS,
  DEFAULT_PORT_WAIT_MS,
  MAX_SPAWN_OUTPUT_BYTES,
};
