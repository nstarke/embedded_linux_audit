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

// When a command is run via `linux execute-command`, the agent's txt record
// formats output as `<command>\n<output>` (see record_formatter.c), so the
// captured output begins with a second echo of the command itself — distinct
// from the REPL input echo dropped above. Strip that leading echo line when it
// matches the command we sent. `commandEcho` is falsy for raw ELA commands
// (`ela/exec`/`ela` spawn), whose output has no such wrapper.
function stripCommandEcho(output, commandEcho) {
  const echo = String(commandEcho || '');
  if (!echo) return output;
  if (output === echo) return '';
  if (output.startsWith(`${echo}\n`)) return output.slice(echo.length + 1);
  return output;
}

// Agents launched by the embedded wrapper emit JSON (ELA_OUTPUT_FORMAT=json).
// When the captured output is a single JSON object/array, return it parsed so
// callers get structured data instead of a JSON string; otherwise return the
// text unchanged (plain-text output, or a command that ignored the format).
function maybeParseJsonOutput(text) {
  const trimmed = String(text).trim();
  if (!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[')) {
    return text;
  }
  try {
    return JSON.parse(trimmed);
  } catch {
    return text;
  }
}

// Extract just the command's output from the raw buffer, given the completion
// prompt index. The output sits between the last echoed-command prompt (the
// input line the REPL echoed back) and the completion prompt; the echoed
// command line itself is dropped, then ANSI/carriage-returns are stripped, and
// finally the `execute-command` record's own command echo (if any) is removed.
function extractExecOutput(buffer, completionIndex, promptToken, commandEcho) {
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
  out = out.replace(/\n+$/, '');
  return stripCommandEcho(out, commandEcho);
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
    // For a shell command the agent echoes it back inside the execute-command
    // record; strip that. A raw ELA command has no such echo.
    const commandEcho = wrapShell ? String(command || '') : null;
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
          output: maybeParseJsonOutput(
            extractExecOutput(buffer, completionIndex, promptToken, commandEcho),
          ),
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
        output: extractExecOutput(buffer, buffer.length, promptToken, commandEcho),
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
  stripCommandEcho,
  maybeParseJsonOutput,
  findCompletionIndex,
  extractExecOutput,
  DEFAULT_EXEC_TIMEOUT_MS,
  MAX_EXEC_OUTPUT_BYTES,
};
