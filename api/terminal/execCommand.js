// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { formatShellExecution } = require('./listCommands');
const { promptTokenForMac } = require('./promptFormatter');

const DEFAULT_EXEC_TIMEOUT_MS = 15000;
// Cap captured output so a runaway command cannot exhaust memory.
const MAX_EXEC_OUTPUT_BYTES = 1024 * 1024;

// Run a single command over an attached session's WebSocket and capture its
// output. Completion is detected by the agent re-emitting its prompt token
// (`(<mac>)> `) once the command has finished and the shell is ready again.
//
// Resolves with { ok: true, output, durationMs } on success.
// Rejects with an Error carrying a `code` of:
//   - 'NOT_CONNECTED' when the session WebSocket is not open
//   - 'TIMEOUT' when no prompt is seen within timeoutMs (carries partial output)
//   - 'SEND_FAILED' when the command could not be written to the socket
function runExec({
  entry,
  mac,
  command,
  timeoutMs = DEFAULT_EXEC_TIMEOUT_MS,
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

    const promptToken = promptTokenForMac(mac);
    const startedAt = now();
    let buffer = '';
    let settled = false;
    let timer = null;

    function cleanup() {
      if (timer) {
        clearTimeoutImpl(timer);
        timer = null;
      }
      entry.outputListeners.delete(onOutput);
    }

    function onOutput(text) {
      if (settled) {
        return;
      }
      buffer += text;
      if (buffer.length > MAX_EXEC_OUTPUT_BYTES) {
        buffer = buffer.slice(-MAX_EXEC_OUTPUT_BYTES);
      }
      const promptIndex = buffer.lastIndexOf(promptToken);
      if (promptIndex >= 0) {
        settled = true;
        cleanup();
        const output = buffer.slice(0, promptIndex).replace(/\r?\n$/, '');
        resolve({ ok: true, output, durationMs: now() - startedAt });
      }
    }

    entry.outputListeners.add(onOutput);

    timer = setTimeoutImpl(() => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(Object.assign(new Error('exec timed out'), {
        code: 'TIMEOUT',
        output: buffer,
        durationMs: now() - startedAt,
      }));
    }, timeoutMs);

    try {
      ws.send(`${formatShellExecution(command)}\n`);
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
  runExec,
  DEFAULT_EXEC_TIMEOUT_MS,
  MAX_EXEC_OUTPUT_BYTES,
};
