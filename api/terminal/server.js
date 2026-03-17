// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const readline = require('readline');
const { WebSocketServer } = require('ws');
const auth = require('../auth');

/* -------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------- */

const PORT = parseInt(process.env.ELA_TERMINAL_PORT || '8080', 10);
const HEARTBEAT_INTERVAL_MS = 30000;
const ALIASES_FILE = path.join(__dirname, 'ela-aliases.json');
const UPDATE_URL = (process.env.ELA_UPDATE_URL || '').replace(/\/+$/, '');

/* -------------------------------------------------------------------------
 * Alias persistence
 * ---------------------------------------------------------------------- */

function loadAliases() {
  try {
    return JSON.parse(fs.readFileSync(ALIASES_FILE, 'utf8'));
  } catch (_) {
    return {};
  }
}

function saveAliases() {
  try {
    fs.writeFileSync(ALIASES_FILE, JSON.stringify(aliases, null, 2), 'utf8');
  } catch (err) {
    process.stderr.write(`Warning: failed to save aliases: ${err.message}\n`);
  }
}

const aliases = loadAliases();
const VALIDATE_KEY = process.argv.includes('--validate-key');

/* -------------------------------------------------------------------------
 * Session registry
 * ---------------------------------------------------------------------- */

// mac -> { ws, mac, alias, lastHeartbeat, heartbeatTimer, outputBuffer }
const sessions = new Map();

function addSession(mac, ws) {
  const entry = {
    ws,
    mac,
    alias: aliases[mac] || null,
    lastHeartbeat: null,
    heartbeatTimer: null,
    outputBuffer: [],
    updateCtx: null,    // active update state machine, or null
    updateStatus: null, // null | 'updating' | 'ok' | 'failed'
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

wss.on('connection', (ws, req) => {
  // Extract MAC from URL: /terminal/<mac>
  const parts = (req.url || '').split('/').filter(Boolean);
  const mac = parts[1] || 'unknown';

  // If a session for this MAC already exists, close the old one
  const existing = sessions.get(mac);
  if (existing) {
    existing.ws.close();
    removeSession(mac);
  }

  const entry = addSession(mac, ws);

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
        return;
      }
    } catch (_) {
      // not JSON — treat as raw output
    }

    // Drive the update state machine regardless of which view is active
    handleUpdateMessage(entry, text);

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
 * Update helpers
 * ---------------------------------------------------------------------- */

/*
 * Map (arch isa, arch endianness) → the ISA directory name used by the
 * agent API's /isa/:isa endpoint (and the release binaries directory).
 * Architectures that only ship one endianness variant use no suffix.
 */
function buildIsaString(isa, endianness) {
  if (isa === 'x86_64' || isa === 'x86' || isa === 'riscv32' || isa === 'riscv64')
    return isa;
  return `${isa}-${endianness === 'big' ? 'be' : 'le'}`;
}

/*
 * Kick off the update state machine for a single session.
 * Returns false if already updating or no UPDATE_URL is configured.
 */
function startSessionUpdate(entry) {
  if (!UPDATE_URL || entry.updateCtx) return false;
  entry.updateCtx = { state: 'await-isa', isa: null, buffer: '' };
  entry.updateStatus = 'updating';
  if (entry.ws.readyState === entry.ws.OPEN) {
    entry.ws.send('\x15'); // cancel any buffered readline input
    entry.ws.send('--output-format json arch isa\n');
  }
  return true;
}

/*
 * Drive the per-session update state machine forward when new text arrives
 * from the agent.  Called from ws.on('message') for every frame.
 */
function handleUpdateMessage(entry, text) {
  const ctx = entry.updateCtx;
  if (!ctx) return;
  ctx.buffer += text;

  if (ctx.state === 'await-isa') {
    // Look for the JSON record emitted by: --output-format json arch isa
    const m = ctx.buffer.match(/\{"record":"arch"[^}]+\}/);
    if (!m) return;
    try {
      const obj = JSON.parse(m[0]);
      if (obj.subcommand !== 'isa' || !obj.value) return;
      ctx.isa = obj.value;
    } catch (_) { return; }
    ctx.buffer = '';
    ctx.state = 'await-endianness';
    if (entry.ws.readyState === entry.ws.OPEN)
      entry.ws.send('--output-format json arch endianness\n');

  } else if (ctx.state === 'await-endianness') {
    const m = ctx.buffer.match(/\{"record":"arch"[^}]+\}/);
    if (!m) return;
    let endianness;
    try {
      const obj = JSON.parse(m[0]);
      if (obj.subcommand !== 'endianness' || !obj.value) return;
      endianness = obj.value;
    } catch (_) { return; }

    const isaStr = buildIsaString(ctx.isa, endianness);
    ctx.buffer = '';
    ctx.state = 'in-progress';
    if (entry.ws.readyState === entry.ws.OPEN) {
      const dlCmd  = `linux download-file ${UPDATE_URL}/isa/${isaStr} /tmp/ela.new\n`;
      const mvCmd  = 'linux execute-command ' +
        '"chmod +x /tmp/ela.new && ' +
        'mv /tmp/ela.new $(readlink -f /proc/self/exe) && ' +
        'echo [UPDATE OK] || echo [UPDATE FAILED]"\n';
      entry.ws.send(dlCmd + mvCmd);
    }

  } else if (ctx.state === 'in-progress') {
    if (text.includes('[UPDATE OK]')) {
      entry.updateCtx = null;
      entry.updateStatus = 'ok';
      if (tui.state === TUI_STATE.ACTIVE_SESSION && tui.activeMac === entry.mac)
        process.stdout.write('\r\n[update complete]\r\n');
      else if (tui.state === TUI_STATE.SESSION_LIST)
        tui.render();
    } else if (text.includes('[UPDATE FAILED]')) {
      entry.updateCtx = null;
      entry.updateStatus = 'failed';
      if (tui.state === TUI_STATE.ACTIVE_SESSION && tui.activeMac === entry.mac)
        process.stdout.write('\r\n[update failed]\r\n');
      else if (tui.state === TUI_STATE.SESSION_LIST)
        tui.render();
    }
  }
}

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
  _listCmd:   null,    // non-null while typing a /command in the session list

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
        const statusTag = entry.updateStatus
          ? `  [${entry.updateStatus}]`
          : '';
        const line = `  ${label}${hb}${statusTag}`;
        if (i === this.cursor) {
          out += `${ANSI.reverse}${line}${ANSI.reset}\r\n`;
        } else {
          out += `${line}\r\n`;
        }
      }
    }

    out += '\r\n' + `${ANSI.dim}↑/↓ navigate   Enter attach   / command   q quit${ANSI.reset}\r\n`;
    if (this._listCmd !== null) {
      out += `/${this._listCmd}`;
    }
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
      this._handleListKey(key, name, ctrl);
    } else {
      this._handleSessionKey(key, name, ctrl);
    }
  },

  _handleListKey(key, name, ctrl) {
    const macs = [...sessions.keys()];

    // Command-input mode: user pressed '/' and is typing a command
    if (this._listCmd !== null) {
      if (name === 'return') {
        const cmd = this._listCmd;
        this._listCmd = null;
        this._executeListCommand(cmd);
        return;
      }
      if (name === 'escape' || (ctrl && name === 'c')) {
        this._listCmd = null;
        this.render();
        return;
      }
      if (name === 'backspace') {
        if (this._listCmd.length > 0) this._listCmd = this._listCmd.slice(0, -1);
        this.render();
        return;
      }
      if (key && key.length === 1 && key.charCodeAt(0) >= 0x20 && key.charCodeAt(0) < 0x7f) {
        this._listCmd += key;
        this.render();
        return;
      }
      return;
    }

    // '/' starts command-input mode
    if (key === '/') {
      this._listCmd = '';
      this.render();
      return;
    }

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
      cleanup();
      process.exit(0);
    }
  },

  _executeListCommand(cmd) {
    if (cmd === 'update-all') {
      if (!UPDATE_URL) {
        process.stdout.write('\r\n[update: ELA_UPDATE_URL is not set]\r\n');
        this.render();
        return;
      }
      const macs = [...sessions.keys()];
      if (macs.length === 0) {
        process.stdout.write('\r\n[update: no connected sessions]\r\n');
        this.render();
        return;
      }
      let started = 0;
      for (const mac of macs) {
        const entry = sessions.get(mac);
        if (entry && startSessionUpdate(entry)) started++;
      }
      process.stdout.write(`\r\n[update: initiated for ${started} session(s)]\r\n`);
      this.render();
    } else if (cmd === '') {
      this.render();
    } else {
      process.stdout.write(`\r\n[unknown command: /${cmd}]\r\n`);
      this.render();
    }
  },

  _handleSessionKey(key, name, ctrl) {
    if (ctrl && name === 'c') {
      cleanup();
      process.exit(0);
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
      if (cmd === '/exit-all') {
        // Cancel any buffered input on the current agent's readline first.
        if (entry && entry.ws.readyState === entry.ws.OPEN)
          entry.ws.send('\x15');
        // Send 'exit\n' to every connected session to close them all.
        for (const [, sess] of sessions) {
          if (sess.ws.readyState === sess.ws.OPEN)
            sess.ws.send('exit\n');
        }
        process.stdout.write('\r\n');
        this.detach();
        return;
      }
      if (cmd === '/update') {
        if (!UPDATE_URL) {
          if (entry && entry.ws.readyState === entry.ws.OPEN)
            entry.ws.send('\x15');
          process.stdout.write('\r\n[update: ELA_UPDATE_URL is not set]\r\n');
          return;
        }
        const activeEntry = sessions.get(this.activeMac);
        if (activeEntry) {
          if (!startSessionUpdate(activeEntry)) {
            if (entry && entry.ws.readyState === entry.ws.OPEN)
              entry.ws.send('\x15');
            process.stdout.write('\r\n[update: already in progress]\r\n');
          } else {
            process.stdout.write('\r\n[update: detecting architecture...]\r\n');
          }
        }
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
          if (arg) {
            sessionEntry.alias = arg;
            aliases[mac] = arg;
          } else {
            sessionEntry.alias = null;
            delete aliases[mac];
          }
          saveAliases();
          process.stdout.write(`\r\n[alias ${arg ? `set to "${arg}"` : 'cleared'}]\r\n`);
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

function cleanup() {
  for (const [mac] of sessions) {
    removeSession(mac);
  }
  if (process.stdin.isTTY) {
    process.stdin.setRawMode(false);
  }
  process.stdout.write(ANSI.reset + '\r\n');
}

process.on('SIGINT', () => { cleanup(); process.exit(0); });
process.on('SIGTERM', () => { cleanup(); process.exit(0); });

if (!auth.init(path.join(__dirname, '..', 'ela.key'), VALIDATE_KEY)) {
  process.stderr.write(
    'error: --validate-key is set but ela.key is missing or contains no valid tokens\n'
  );
  process.exit(1);
}

httpServer.listen(PORT, () => {
  setupInput();
  tui.render();
});
