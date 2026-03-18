// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

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
const { loadLegacyAliases } = require('./legacyAliases');
const { createSessionRegistry } = require('./sessionRegistry');
const { formatListCommandHelp, formatShellExecution, isAffirmativeResponse, parseListCommand } = require('./listCommands');
const { executeLocalSessionCommand } = require('./localCommands');
const { createTerminalHttpHandler } = require('./httpRoutes');
const { startSessionUpdate, handleUpdateMessage } = require('./updateManager');
const {
  PASSTHROUGH_EXIT_HINT,
  PASSTHROUGH_EXIT_SEQUENCE,
  remoteInputForKeypress,
  shouldEnterPassthrough,
} = require('./sessionInput');

const terminalConfig = getTerminalServiceConfig();
const HOST = terminalConfig.host;
const PORT = terminalConfig.port;
const HEARTBEAT_INTERVAL_MS = 30000;
const LEGACY_ALIASES_FILE = `${__dirname}/ela-aliases.json`;
const VALIDATE_KEY = process.argv.includes('--validate-key');

async function importLegacyAliases() {
  const aliases = loadLegacyAliases(LEGACY_ALIASES_FILE);
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

const sessionRegistry = createSessionRegistry({ heartbeatIntervalMs: HEARTBEAT_INTERVAL_MS });

async function cleanup() {
  const closeOps = [];
  for (const [mac, entry] of sessionRegistry.entries()) {
    if (entry.connectionId) {
      closeOps.push(closeTerminalConnection(entry.connectionId).catch(() => {}));
    }
    sessionRegistry.removeSession(mac);
  }
  await Promise.all(closeOps);
  if (process.stdin.isTTY) {
    process.stdin.setRawMode(false);
  }
  process.stdout.write(ANSI.reset + '\r\n');
}

function exitGracefully() {
  cleanup()
    .then(() => closeDatabase().catch(() => {}))
    .finally(() => process.exit(0));
}

const httpServer = http.createServer(createTerminalHttpHandler());

function onUpdateStateTransition(entry, message) {
  if (tui.state === TUI_STATE.ACTIVE_SESSION && tui.activeMac === entry.mac) {
    process.stdout.write(`\r\n[${message}]\r\n`);
  } else if (tui.state === TUI_STATE.SESSION_LIST) {
    tui.render();
  }
}

const wss = new WebSocketServer({
  server: httpServer,
  verifyClient(info, done) {
    const url = info.req.url || '';
    if (!url.startsWith('/terminal/')) {
      done(false, 404, 'Not Found');
      return;
    }
    if (auth.checkBearer(info.req.headers.authorization)) {
      done(true);
    } else {
      done(false, 401, 'Unauthorized');
    }
  },
});

wss.on('connection', async (ws, req) => {
  const parts = (req.url || '').split('/').filter(Boolean);
  const mac = parts[1] || 'unknown';

  const existing = sessionRegistry.getSession(mac);
  if (existing) {
    existing.ws.close();
    sessionRegistry.removeSession(mac);
  }

  let registration;
  try {
    registration = await recordTerminalConnection(mac, req.socket?.remoteAddress || null);
  } catch (err) {
    ws.close(1011, 'database unavailable');
    process.stderr.write(`Failed to register terminal connection for ${mac}: ${err.message}\n`);
    return;
  }

  const entry = sessionRegistry.addSession(mac, ws, {
    alias: registration.alias,
    connectionId: registration.connectionId,
  });
  entry.updateCtx = null;
  entry.updateStatus = null;

  if (tui.state === TUI_STATE.SESSION_LIST) {
    tui.render();
  }

  ws.on('message', (data) => {
    const text = data.toString();

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
    } catch {
      // raw output path
    }

    handleUpdateMessage(entry, text, {
      onUpdateComplete: (sessionEntry) => onUpdateStateTransition(sessionEntry, 'update complete'),
      onUpdateFailed: (sessionEntry) => onUpdateStateTransition(sessionEntry, 'update failed'),
    });

    if (tui.state === TUI_STATE.ACTIVE_SESSION && tui.activeMac === mac) {
      process.stdout.write(text);
    } else {
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
    sessionRegistry.removeSession(mac);
    if (tui.state === TUI_STATE.ACTIVE_SESSION && tui.activeMac === mac) {
      process.stdout.write('\r\n[session disconnected]\r\n');
      tui.detach();
    } else if (tui.state === TUI_STATE.SESSION_LIST) {
      tui.render();
    }
  });

  ws.on('error', () => {
    sessionRegistry.removeSession(mac);
  });
});

const TUI_STATE = { SESSION_LIST: 'SESSION_LIST', ACTIVE_SESSION: 'ACTIVE_SESSION' };

const ANSI = {
  clear: '\x1b[2J\x1b[H',
  reset: '\x1b[0m',
  reverse: '\x1b[7m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
};

const tui = {
  state: TUI_STATE.SESSION_LIST,
  cursor: 0,
  activeMac: null,
  _listCmd: null,
  _confirmPrompt: null,
  _confirmValue: '',
  _confirmAction: null,
  _statusMsg: null,

  render() {
    if (this.state !== TUI_STATE.SESSION_LIST) {
      return;
    }

    const macs = sessionRegistry.listMacs();
    let out = ANSI.clear;
    out += `${ANSI.bold}ela-terminal${ANSI.reset}  —  ${macs.length} session(s)\r\n`;
    out += '─'.repeat(60) + '\r\n';

    if (macs.length === 0) {
      out += `${ANSI.dim}  (no connected devices)${ANSI.reset}\r\n`;
    } else {
      for (let i = 0; i < macs.length; i += 1) {
        const mac = macs[i];
        const entry = sessionRegistry.getSession(mac);
        const hb = entry.lastHeartbeat ? `  last heartbeat: ${entry.lastHeartbeat}` : '';
        const label = entry.alias ? `${entry.alias} (${mac})` : mac;
        const statusTag = entry.updateStatus ? `  [${entry.updateStatus}]` : '';
        const line = `  ${label}${hb}${statusTag}`;
        out += i === this.cursor
          ? `${ANSI.reverse}${line}${ANSI.reset}\r\n`
          : `${line}\r\n`;
      }
    }

    out += `\r\n${ANSI.dim}↑/↓ navigate   Enter attach   / command   q quit${ANSI.reset}\r\n`;
    if (this._confirmPrompt !== null) {
      out += `${this._confirmPrompt} ${this._confirmValue}`;
    } else {
      if (this._statusMsg !== null) {
        out += `${ANSI.dim}${this._statusMsg}${ANSI.reset}\r\n`;
        this._statusMsg = null;
      }
      if (this._listCmd !== null) {
        out += `/${this._listCmd}`;
      }
    }
    process.stdout.write(out);
  },

  attach(mac) {
    const entry = sessionRegistry.getSession(mac);
    if (!entry) {
      return;
    }

    this.state = TUI_STATE.ACTIVE_SESSION;
    this.activeMac = mac;
    this._localCmdBuf = '';

    const label = entry.alias ? `${entry.alias} (${mac})` : mac;
    process.stdout.write(ANSI.clear);
    process.stdout.write(
      `${ANSI.bold}Attached to ${label}${ANSI.reset}  (type '/detach' + Enter to return)\r\n` +
      '─'.repeat(60) + '\r\n',
    );

    if (entry.outputBuffer.length > 0) {
      process.stdout.write(entry.outputBuffer.join(''));
      entry.outputBuffer = [];
    }
  },

  detach() {
    this.state = TUI_STATE.SESSION_LIST;
    const entry = this.activeMac ? sessionRegistry.getSession(this.activeMac) : null;
    if (entry) {
      entry.inputMode = 'line';
    }
    this.activeMac = null;
    const count = sessionRegistry.size;
    if (this.cursor >= count) {
      this.cursor = Math.max(0, count - 1);
    }
    this.render();
  },

  handleKey(key, name, ctrl) {
    if (this.state === TUI_STATE.SESSION_LIST) {
      this._handleListKey(key, name, ctrl);
    } else {
      void this._handleSessionKey(key, name, ctrl);
    }
  },

  _handleListKey(key, name, ctrl) {
    const macs = sessionRegistry.listMacs();

    if (this._confirmPrompt !== null) {
      if (name === 'return') {
        const accepted = isAffirmativeResponse(this._confirmValue);
        const action = this._confirmAction;
        this._confirmPrompt = null;
        this._confirmValue = '';
        this._confirmAction = null;
        if (accepted && action) {
          action();
        } else {
          process.stdout.write('\r\n[cancelled]\r\n');
          this.render();
        }
        return;
      }
      if (name === 'escape' || (ctrl && name === 'c')) {
        this._confirmPrompt = null;
        this._confirmValue = '';
        this._confirmAction = null;
        process.stdout.write('\r\n[cancelled]\r\n');
        this.render();
        return;
      }
      if (name === 'backspace') {
        if (this._confirmValue.length > 0) {
          this._confirmValue = this._confirmValue.slice(0, -1);
        }
        this.render();
        return;
      }
      if (key && key.length === 1 && key.charCodeAt(0) >= 0x20 && key.charCodeAt(0) < 0x7f) {
        this._confirmValue += key;
        this.render();
      }
      return;
    }

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
        if (this._listCmd.length > 0) {
          this._listCmd = this._listCmd.slice(0, -1);
        }
        this.render();
        return;
      }
      if (key && key.length === 1 && key.charCodeAt(0) >= 0x20 && key.charCodeAt(0) < 0x7f) {
        this._listCmd += key;
        this.render();
      }
      return;
    }

    if (key === '/') {
      this._listCmd = '';
      this.render();
      return;
    }

    if (name === 'up' || name === 'k') {
      if (this.cursor > 0) {
        this.cursor -= 1;
      }
      this.render();
    } else if (name === 'down' || name === 'j') {
      if (this.cursor < macs.length - 1) {
        this.cursor += 1;
      }
      this.render();
    } else if (name === 'return' && macs.length > 0) {
      const mac = macs[this.cursor];
      if (mac) {
        this.attach(mac);
      }
    } else if (name === 'q' || (ctrl && name === 'c')) {
      exitGracefully();
    }
  },

  _executeListCommand(cmd) {
    const parsed = parseListCommand(cmd);

    if (parsed.type === 'help') {
      this._statusMsg = formatListCommandHelp();
      this.render();
      return;
    }

    if (parsed.type === 'update') {
      const macs = sessionRegistry.listMacs();
      if (macs.length === 0) {
        this._statusMsg = 'update: no connected sessions';
        this.render();
        return;
      }
      let started = 0;
      for (const mac of macs) {
        const entry = sessionRegistry.getSession(mac);
        if (entry && startSessionUpdate(entry)) {
          started += 1;
        }
      }
      this._statusMsg = `update: initiated for ${started} session(s)`;
      this.render();
      return;
    }

    if (parsed.type === 'exit') {
      const macs = sessionRegistry.listMacs();
      if (macs.length === 0) {
        this._statusMsg = 'exit: no connected sessions';
        this.render();
        return;
      }

      this._confirmPrompt = `[confirm: run "exit" on ${macs.length} node(s)? y/N]`;
      this._confirmValue = '';
      this._confirmAction = () => {
        let started = 0;
        for (const mac of sessionRegistry.listMacs()) {
          const entry = sessionRegistry.getSession(mac);
          if (entry && entry.ws.readyState === entry.ws.OPEN) {
            entry.ws.send('exit\n');
            started += 1;
          }
        }
        this._statusMsg = `exit: launched on ${started} node(s)`;
        this.render();
      };
      this.render();
      return;
    }

    if (parsed.type === 'shell-all') {
      const macs = sessionRegistry.listMacs();
      if (macs.length === 0) {
        this._statusMsg = 'shell: no connected sessions';
        this.render();
        return;
      }

      this._confirmPrompt = `[confirm: run "${formatShellExecution(parsed.command)}" on ${macs.length} node(s)? y/N]`;
      this._confirmValue = '';
      this._confirmAction = () => {
        let started = 0;
        for (const mac of sessionRegistry.listMacs()) {
          const entry = sessionRegistry.getSession(mac);
          if (entry && entry.ws.readyState === entry.ws.OPEN) {
            entry.ws.send(`${formatShellExecution(parsed.command)}\n`);
            started += 1;
          }
        }
        this._statusMsg = `shell: launched on ${started} node(s)`;
        this.render();
      };
      this.render();
      return;
    }

    if (parsed.type === 'cmd-all') {
      const macs = sessionRegistry.listMacs();
      if (macs.length === 0) {
        this._statusMsg = 'cmd: no connected sessions';
        this.render();
        return;
      }

      this._confirmPrompt = `[confirm: run "${parsed.command}" on ${macs.length} node(s)? y/N]`;
      this._confirmValue = '';
      this._confirmAction = () => {
        let started = 0;
        for (const mac of sessionRegistry.listMacs()) {
          const entry = sessionRegistry.getSession(mac);
          if (entry && entry.ws.readyState === entry.ws.OPEN) {
            entry.ws.send(`${parsed.command}\n`);
            started += 1;
          }
        }
        this._statusMsg = `cmd: launched on ${started} node(s)`;
        this.render();
      };
      this.render();
      return;
    }

    if (parsed.type === 'set-all') {
      const macs = sessionRegistry.listMacs();
      if (macs.length === 0) {
        this._statusMsg = 'set: no connected sessions';
        this.render();
        return;
      }

      let started = 0;
      for (const mac of sessionRegistry.listMacs()) {
        const entry = sessionRegistry.getSession(mac);
        if (entry && entry.ws.readyState === entry.ws.OPEN) {
          entry.ws.send(`set ${parsed.key} ${parsed.value}\n`);
          started += 1;
        }
      }
      this._statusMsg = `set: dispatched "${parsed.key}" to ${started} node(s)`;
      this.render();
      return;
    }

    if (parsed.type === 'invalid-shell') {
      this._statusMsg = 'usage: /shell <command>';
      this.render();
      return;
    }

    if (parsed.type === 'invalid-cmd') {
      this._statusMsg = 'usage: /cmd <command>';
      this.render();
      return;
    }

    if (parsed.type === 'invalid-set') {
      this._statusMsg = 'usage: /set <key> <value>';
      this.render();
      return;
    }

    if (parsed.type === 'unknown') {
      this._statusMsg = `unknown command: /${parsed.raw}`;
    }
    this.render();
  },

  async _handleSessionKey(key, name, ctrl) {
    const entry = sessionRegistry.getSession(this.activeMac);
    if (entry && entry.inputMode === 'passthrough') {
      if (key === PASSTHROUGH_EXIT_SEQUENCE || (ctrl && name === ']')) {
        entry.inputMode = 'line';
        this._localCmdBuf = '';
        process.stdout.write(`\r\n[passthrough mode disabled; '/detach' is available again]\r\n`);
        return;
      }

      const remoteInput = remoteInputForKeypress(key, name);
      if (remoteInput && entry.ws.readyState === entry.ws.OPEN) {
        entry.ws.send(remoteInput);
      }
      return;
    }

    if (ctrl && name === 'c') {
      exitGracefully();
      return;
    }

    if (this._localCmdBuf === undefined) {
      this._localCmdBuf = '';
    }

    if (name === 'return') {
      const cmd = this._localCmdBuf;
      this._localCmdBuf = '';
      try {
        const handled = await executeLocalSessionCommand({
          cmd,
          activeMac: this.activeMac,
          sessionEntry: entry,
          sessions: sessionRegistry.entries().map(([, sessionEntry]) => sessionEntry),
          setDeviceAlias,
          startSessionUpdate,
          onDetach: () => this.detach(),
          writeOutput: (text) => process.stdout.write(text),
          cancelRemoteInput: () => {
            if (entry && entry.ws.readyState === entry.ws.OPEN) {
              entry.ws.send('\x15');
            }
          },
        });
        if (handled) {
          return;
        }
      } catch (err) {
        process.stdout.write(`\r\n[failed to save alias: ${err.message}]\r\n`);
        return;
      }

      if (entry && shouldEnterPassthrough(cmd)) {
        entry.inputMode = 'passthrough';
        process.stdout.write(`\r\n[passthrough mode enabled; press ${PASSTHROUGH_EXIT_HINT} to return to line mode]\r\n`);
      }

      if (entry && entry.ws.readyState === entry.ws.OPEN) {
        entry.ws.send('\n');
      }
      return;
    }

    if (key && key.length === 1 && key.charCodeAt(0) >= 0x20 && key.charCodeAt(0) < 0x7f) {
      this._localCmdBuf += key;
      if (entry && entry.ws.readyState === entry.ws.OPEN) {
        entry.ws.send(key);
      }
      return;
    }

    if (name === 'backspace') {
      if (this._localCmdBuf.length > 0) {
        this._localCmdBuf = this._localCmdBuf.slice(0, -1);
      }
      if (entry && entry.ws.readyState === entry.ws.OPEN) {
        entry.ws.send('\x7f');
      }
      return;
    }

    this._localCmdBuf = '';

    if (!entry || entry.ws.readyState !== entry.ws.OPEN) {
      return;
    }

    const remoteInput = remoteInputForKeypress(key, name);
    if (remoteInput) {
      entry.ws.send(remoteInput);
    }
  },
};

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

process.on('SIGINT', () => {
  exitGracefully();
});

process.on('SIGTERM', () => {
  exitGracefully();
});

async function main() {
  if (!auth.init(terminalConfig.keyPath, VALIDATE_KEY)) {
    process.stderr.write('error: --validate-key is set but ela.key is missing or contains no valid tokens\n');
    process.exit(1);
  }

  await initializeDatabase();
  await runMigrations();
  await importLegacyAliases();

  httpServer.listen(PORT, HOST, () => {
    setupInput();
    process.stdout.write(`ELA terminal API listening on ws://${HOST}:${PORT}\n`);
    tui.render();
  });
}

main().catch(async (err) => {
  process.stderr.write(`${err.stack || err.message}\n`);
  try {
    await closeDatabase();
  } catch {
    // ignore shutdown errors
  }
  process.exit(1);
});
