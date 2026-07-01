// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { formatShellExecution } = require('./listCommands');
const { promptTokenForMac } = require('./promptFormatter');

const DEFAULT_EXEC_TIMEOUT_MS = 15000;
// Cap captured output so a runaway command cannot exhaust memory.
const MAX_EXEC_OUTPUT_BYTES = 1024 * 1024;

// CSI / OSC escape sequences emitted by the agent's interactive line editor.
const ANSI_RE = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
const OSC_RE = /\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g;

function stripAnsi(text) {
  return String(text).replace(ANSI_RE, '').replace(OSC_RE, '');
}

// Locate the command's *completion* prompt in the captured buffer.
//
// The agent runs an interactive REPL that echoes input while it is being
// "typed", redrawing the prompt on the same line with carriage-return / clear
// sequences (e.g. `\r\x1b[2K(mac)> lin`). Those echoed prompts must NOT be
// treated as completion. After `formatPromptOutput`, only the real prompt that
// follows command output is preceded by a newline, so a prompt token whose
// preceding character is `\n` marks completion. Returns its index, or -1.
function findCompletionIndex(buffer, promptToken) {
  let from = 0;
  for (;;) {
    const idx = buffer.indexOf(promptToken, from);
    if (idx < 0) return -1;
    if (idx > 0 && buffer[idx - 1] === '\n') return idx;
    from = idx + promptToken.length;
  }
}

// Extract just the command's output from the raw buffer, given the completion
// prompt index. The output sits between the last echoed-command prompt (the
// input line the REPL echoed back) and the completion prompt; the echoed
// command line itself is dropped, then ANSI/carriage-returns are stripped.
function extractExecOutput(buffer, completionIndex, promptToken) {
  const region = buffer.slice(0, completionIndex);
  const lastPrompt = region.lastIndexOf(promptToken);
  let out;
  if (lastPrompt >= 0) {
    // The input echo left a `(mac)> <command>` line just before the output; drop
    // that echoed command line (up to and including its newline).
    out = region.slice(lastPrompt + promptToken.length).replace(/^[^\n]*\n/, '');
  } else {
    // No echoed prompt captured — the region is the output itself.
    out = region;
  }
  out = stripAnsi(out).replace(/\r/g, '');
  return out.replace(/\n+$/, '');
}

/**
 * Run a single command over an attached session's WebSocket and capture its
 * output.
 *
 * @param {object} opts
 * @param {object} opts.entry     Live session entry (has `.ws`, `.outputListeners`).
 * @param {string} opts.mac
 * @param {string} opts.command
 * @param {number} [opts.timeoutMs]
 * @param {boolean} [opts.wrapShell=true]  When true the command is a Linux shell
 *   command and is wrapped as `linux execute-command "<cmd>"`; when false the
 *   command is sent verbatim as an ELA agent command (e.g. `linux gdbserver ...`).
 *
 * Resolves with { ok: true, output, durationMs } on success. Rejects with an
 * Error carrying `code`:
 *   - 'NOT_CONNECTED' when the session WebSocket is not open
 *   - 'TIMEOUT' when no completion prompt is seen within timeoutMs (carries
 *     the partial output captured so far)
 *   - 'SEND_FAILED' when the command could not be written to the socket
 */
function runExec({
  entry,
  mac,
  command,
  timeoutMs = DEFAULT_EXEC_TIMEOUT_MS,
  wrapShell = true,
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
      const completionIndex = findCompletionIndex(buffer, promptToken);
      if (completionIndex >= 0) {
        settled = true;
        cleanup();
        resolve({
          ok: true,
          output: extractExecOutput(buffer, completionIndex, promptToken),
          durationMs: now() - startedAt,
        });
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
        output: extractExecOutput(buffer, buffer.length, promptToken),
        durationMs: now() - startedAt,
      }));
    }, timeoutMs);

    try {
      const line = wrapShell ? formatShellExecution(command) : String(command || '');
      ws.send(`${line}\n`);
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
  stripAnsi,
  findCompletionIndex,
  extractExecOutput,
  DEFAULT_EXEC_TIMEOUT_MS,
  MAX_EXEC_OUTPUT_BYTES,
};
