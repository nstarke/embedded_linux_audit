// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const fs = require('fs');
const http = require('http');
const readline = require('readline');
const { WebSocketServer } = require('ws');
const auth = require('../auth');
const { getTerminalServiceConfig } = require('../lib/config');
const { initializeDatabase, runMigrations, closeDatabase } = require('../lib/db');
const {
  recordTerminalConnection,
  touchTerminalHeartbeat,
  closeTerminalConnection,
  setDeviceAlias,
} = require('../lib/db/deviceRegistry');

/* -------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------- */

const terminalConfig = getTerminalServiceConfig();
const PORT = terminalConfig.port;
const HEARTBEAT_INTERVAL_MS = 30000;
const LEGACY_ALIASES_FILE = `${__dirname}/ela-aliases.json`;

/* -------------------------------------------------------------------------
 * Legacy alias import
 * ---------------------------------------------------------------------- */

function loadLegacyAliases() {
  try {
    return JSON.parse(fs.readFileSync(LEGACY_ALIASES_FILE, 'utf8'));
  } catch (_) {
    return {};
  }
}

async function importLegacyAliases() {
  const aliases = loadLegacyAliases();
  for (const [macAddress, alias] of Object.entries(aliases)) {
    if (!alias) {
      continue;
    }
    try {
      await setDeviceAlias(macAddress, alias, 'legacy_terminal_file');
    } catch (err) {
      process.stderr.write(`Warning: failed to import alias for ${macAddress}: ${err.message}\n`);
    }
  }
}
const VALIDATE_KEY = process.argv.includes('--validate-key');

/* -------------------------------------------------------------------------
 * Session registry
 * ---------------------------------------------------------------------- */

// mac -> { ws, mac, alias, connectionId, lastHeartbeat, heartbeatTimer, outputBuffer }
const sessions = new Map();

function exitGracefully() {
  cleanup()
    .then(() => closeDatabase().catch(() => {}))
    .finally(() => process.exit(0));
}

function addSession(mac, ws, alias, connectionId) {
  const entry = {
    ws,
    mac,
    alias: alias || null,
    connectionId,
    lastHeartbeat: null,
    heartbeatTimer: null,
    outputBuffer: [],
  };

  entry.heartbeatTimer = setInterval(() => {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify({ _type: 'heartbeat' }));
    }
  }, HEARTBEAT_INTERVAL_MS);

  sessions.set(mac, entry);
  return entry;
}

function removeSession(mac) {
  const entry = sessions.get(mac);
  if (entry) {
    clearInterval(entry.heartbeatTimer);
    sessions.delete(mac);
  }
}

/* -------------------------------------------------------------------------
 * WebSocket server
 * ---------------------------------------------------------------------- */

const httpServer = http.createServer((req, res) => {
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({
  server: httpServer,
  verifyClient(info, done) {
    const url = info.req.url || '';
    if (!url.startsWith('/terminal/')) {
      done(false, 404, 'Not Found');
      return;
    }
    if (auth.checkBearer(info.req.headers['authorization'])) {
      done(true);
    } else {
      done(false, 401, 'Unauthorized');
    }
  },
});

wss.on('connection', async (ws, req) => {
  // Extract MAC from URL: /terminal/<mac>
  const parts = (req.url || '').split('/').filter(Boolean);
  const mac = parts[1] || 'unknown';

  // If a session for this MAC already exists, close the old one
  const existing = sessions.get(mac);
  if (existing) {
    existing.ws.close();
    removeSession(mac);
  }

  let registration;
  try {
    registration = await recordTerminalConnection(mac, req.socket?.remoteAddress || null);
  } catch (err) {
    ws.close(1011, 'database unavailable');
    process.stderr.write(`Failed to register terminal connection for ${mac}: ${err.message}\n`);
    return;
  }

  const entry = addSession(mac, ws, registration.alias, registration.connectionId);

  // Notify TUI of new connection
  if (tui.state === TUI_STATE.SESSION_LIST) {
    tui.render();
  }

  ws.on('message', (data) => {
    const text = data.toString();

    // Try to parse heartbeat_ack
    try {
      const msg = JSON.parse(text);
      if (msg._type === 'heartbeat_ack') {
        entry.lastHeartbeat = msg.date || new Date().toISOString();
        if (entry.connectionId) {
          void touchTerminalHeartbeat(entry.connectionId, new Date(entry.lastHeartbeat)).catch((err) => {
            process.stderr.write(`Warning: failed to update heartbeat for ${mac}: ${err.message}\n`);
          });
        }
        return;
      }
    } catch (_) {
      // not JSON — treat as raw output
    }

    // Deliver to TUI if this is the active session
    if (tui.state === TUI_STATE.ACTIVE_SESSION &&
        tui.activeMac === mac) {
      process.stdout.write(text);
    } else {
      // Buffer output for when the session is attached
      entry.outputBuffer.push(text);
      if (entry.outputBuffer.length > 500) {
        entry.outputBuffer.shift();
      }
    }
  });

  ws.on('close', () => {
    if (entry.connectionId) {
      void closeTerminalConnection(entry.connectionId).catch((err) => {
        process.stderr.write(`Warning: failed to close terminal connection for ${mac}: ${err.message}\n`);
      });
    }
    removeSession(mac);
    if (tui.state === TUI_STATE.ACTIVE_SESSION && tui.activeMac === mac) {
      process.stdout.write('\r\n[session disconnected]\r\n');
      tui.detach();
    } else if (tui.state === TUI_STATE.SESSION_LIST) {
      tui.render();
    }
  });

  ws.on('error', () => {
    removeSession(mac);
  });
});

/* -------------------------------------------------------------------------
 * TUI
 * ---------------------------------------------------------------------- */

const TUI_STATE = { SESSION_LIST: 'SESSION_LIST', ACTIVE_SESSION: 'ACTIVE_SESSION' };

const ANSI = {
  clear:       '\x1b[2J\x1b[H',
  reset:       '\x1b[0m',
  reverse:     '\x1b[7m',
  bold:        '\x1b[1m',
  dim:         '\x1b[2m',
  eraseLine:   '\x1b[2K\r',
};

const tui = {
  state:      TUI_STATE.SESSION_LIST,
  cursor:     0,       // index in session list
  activeMac:  null,

  render() {
    if (this.state !== TUI_STATE.SESSION_LIST) return;

    const macs = [...sessions.keys()];
    let out = ANSI.clear;
    out += `${ANSI.bold}ela-terminal${ANSI.reset}  —  ${macs.length} session(s)\r\n`;
    out += '─'.repeat(60) + '\r\n';

    if (macs.length === 0) {
      out += `${ANSI.dim}  (no connected devices)${ANSI.reset}\r\n`;
    } else {
      for (let i = 0; i < macs.length; i++) {
        const mac = macs[i];
        const entry = sessions.get(mac);
        const hb = entry.lastHeartbeat
          ? `  last heartbeat: ${entry.lastHeartbeat}`
          : '';
        const label = entry.alias ? `${entry.alias} (${mac})` : mac;
        const line = `  ${label}${hb}`;
        if (i === this.cursor) {
          out += `${ANSI.reverse}${line}${ANSI.reset}\r\n`;
        } else {
          out += `${line}\r\n`;
        }
      }
    }

    out += '\r\n' + `${ANSI.dim}↑/↓ navigate   Enter attach   q quit${ANSI.reset}\r\n`;
    process.stdout.write(out);
  },

  attach(mac) {
    const entry = sessions.get(mac);
    if (!entry) return;

    this.state        = TUI_STATE.ACTIVE_SESSION;
    this.activeMac    = mac;
    this._localCmdBuf = '';

    const label = entry.alias ? `${entry.alias} (${mac})` : mac;
    process.stdout.write(ANSI.clear);
    process.stdout.write(
      `${ANSI.bold}Attached to ${label}${ANSI.reset}  (type '/detach' + Enter to return)\r\n` +
      '─'.repeat(60) + '\r\n'
    );

    // Flush buffered output; the agent's own prompt is included in the buffer
    if (entry.outputBuffer.length > 0) {
      process.stdout.write(entry.outputBuffer.join(''));
      entry.outputBuffer = [];
    }
  },

  detach() {
    this.state     = TUI_STATE.SESSION_LIST;
    this.activeMac = null;
    // Clamp cursor
    const count = sessions.size;
    if (this.cursor >= count) this.cursor = Math.max(0, count - 1);
    this.render();
  },

  handleKey(key, name, ctrl) {
    if (this.state === TUI_STATE.SESSION_LIST) {
      this._handleListKey(name, ctrl);
    } else {
      this._handleSessionKey(key, name, ctrl);
    }
  },

  _handleListKey(name, ctrl) {
    const macs = [...sessions.keys()];

    if (name === 'up' || name === 'k') {
      if (this.cursor > 0) this.cursor--;
      this.render();
    } else if (name === 'down' || name === 'j') {
      if (this.cursor < macs.length - 1) this.cursor++;
      this.render();
    } else if (name === 'return' && macs.length > 0) {
      const mac = macs[this.cursor];
      if (mac) this.attach(mac);
    } else if (name === 'q' || (ctrl && name === 'c')) {
      exitGracefully();
    }
  },

  _handleSessionKey(key, name, ctrl) {
    if (ctrl && name === 'c') {
      exitGracefully();
      return;
    }

    const entry = sessions.get(this.activeMac);

    /*
     * /detach and /name are local TUI commands — intercept before forwarding.
     * Everything else (including Enter, Tab, arrows, printable chars,
     * backspace) is forwarded raw to the agent.
     */
    if (this._localCmdBuf === undefined)
      this._localCmdBuf = '';

    if (name === 'return') {
      const cmd = this._localCmdBuf;
      this._localCmdBuf = '';
      if (cmd === '/detach') {
        // Cancel the typed chars on the agent's readline before detaching.
        if (entry && entry.ws.readyState === entry.ws.OPEN)
          entry.ws.send('\x15');
        process.stdout.write('\r\n');
        this.detach();
        return;
      }
      if (cmd === '/name' || cmd.startsWith('/name ')) {
        // Cancel the typed chars on the agent's readline.
        if (entry && entry.ws.readyState === entry.ws.OPEN)
          entry.ws.send('\x15');
        const arg = cmd.slice(6).trim();  // everything after '/name '
        const mac = this.activeMac;
        const sessionEntry = sessions.get(mac);
        if (sessionEntry) {
          setDeviceAlias(mac, arg || null, 'terminal_api')
            .then(() => {
              sessionEntry.alias = arg || null;
              process.stdout.write(`\r\n[alias ${arg ? `set to "${arg}"` : 'cleared'}]\r\n`);
            })
            .catch((err) => {
              process.stdout.write(`\r\n[failed to save alias: ${err.message}]\r\n`);
            });
        }
        return;
      }
      // Not a local command — send the buffered bytes + newline to the agent
      if (entry && entry.ws.readyState === entry.ws.OPEN) {
        if (cmd) entry.ws.send(cmd);
        entry.ws.send('\n');
      }
      return;
    }

    // Accumulate printable chars in localCmdBuf so we can detect /detach.
    // Exclude DEL (0x7f) — it has charCode 127 >= 0x20 but is not printable.
    if (key && key.length === 1 && key.charCodeAt(0) >= 0x20 && key.charCodeAt(0) < 0x7f) {
      this._localCmdBuf += key;
      if (entry && entry.ws.readyState === entry.ws.OPEN)
        entry.ws.send(key);
      return;
    }

    // Backspace: erase last char from localCmdBuf (not clear entirely) and
    // forward to agent so its readline stays in sync.
    if (name === 'backspace') {
      if (this._localCmdBuf.length > 0)
        this._localCmdBuf = this._localCmdBuf.slice(0, -1);
      if (entry && entry.ws.readyState === entry.ws.OPEN)
        entry.ws.send('\x7f');
      return;
    }

    // Reset localCmdBuf on any other non-printable key.
    this._localCmdBuf = '';

    if (!entry || entry.ws.readyState !== entry.ws.OPEN)
      return;

    if (name === 'tab')        { entry.ws.send('\t');      return; }
    if (name === 'up')         { entry.ws.send('\x1b[A'); return; }
    if (name === 'down')       { entry.ws.send('\x1b[B'); return; }
    if (name === 'left')       { entry.ws.send('\x1b[D'); return; }
    if (name === 'right')      { entry.ws.send('\x1b[C'); return; }
  },
};

/* -------------------------------------------------------------------------
 * stdin raw-mode keypress handling
 * ---------------------------------------------------------------------- */

function setupInput() {
  if (!process.stdin.isTTY) {
    process.stderr.write('Warning: stdin is not a TTY; interactive TUI unavailable.\n');
    return;
  }

  readline.emitKeypressEvents(process.stdin);
  process.stdin.setRawMode(true);

  process.stdin.on('keypress', (key, info) => {
    const name = info && info.name;
    const ctrl = info && info.ctrl;
    tui.handleKey(key, name, ctrl);
  });
}

/* -------------------------------------------------------------------------
 * Startup / shutdown
 * ---------------------------------------------------------------------- */

async function cleanup() {
  const closeOps = [];
  for (const [mac, entry] of sessions) {
    if (entry.connectionId) {
      closeOps.push(closeTerminalConnection(entry.connectionId).catch(() => {}));
    }
    removeSession(mac);
  }
  await Promise.all(closeOps);
  if (process.stdin.isTTY) {
    process.stdin.setRawMode(false);
  }
  process.stdout.write(ANSI.reset + '\r\n');
}

process.on('SIGINT', async () => {
  exitGracefully();
});
process.on('SIGTERM', async () => {
  exitGracefully();
});

async function main() {
  if (!auth.init(terminalConfig.keyPath, VALIDATE_KEY)) {
    process.stderr.write(
      'error: --validate-key is set but ela.key is missing or contains no valid tokens\n'
    );
    process.exit(1);
  }

  await initializeDatabase();
  await runMigrations();
  await importLegacyAliases();

  httpServer.listen(PORT, () => {
    setupInput();
    tui.render();
  });
}

main().catch(async (err) => {
  process.stderr.write(`${err.stack || err.message}\n`);
  try {
    await closeDatabase();
  } catch (_) {
    // ignore shutdown errors
  }
  process.exit(1);
});
