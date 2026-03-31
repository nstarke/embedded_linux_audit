'use strict';

function createFakeSessionRegistry() {
  const sessions = new Map();
  return {
    addSession(mac, ws, { alias = null, connectionId = null } = {}) {
      const entry = {
        ws,
        mac,
        alias,
        connectionId,
        inputMode: 'line',
        lastHeartbeat: null,
        outputBuffer: [],
        heartbeatTimer: null,
      };
      sessions.set(mac, entry);
      return entry;
    },
    removeSession(mac) {
      sessions.delete(mac);
    },
    getSession(mac) {
      return sessions.get(mac);
    },
    listMacs() {
      return [...sessions.keys()];
    },
    entries() {
      return [...sessions.entries()];
    },
    get size() {
      return sessions.size;
    },
  };
}

function createFakeWs() {
  const handlers = new Map();
  return {
    OPEN: 1,
    readyState: 1,
    handlers,
    on: jest.fn((event, handler) => {
      handlers.set(event, handler);
    }),
    send: jest.fn(),
    close: jest.fn(),
  };
}

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

function loadTerminalServer(options = {}) {
  jest.resetModules();

  const sessionRegistry = createFakeSessionRegistry();
  const readlineMock = {
    emitKeypressEvents: jest.fn(),
  };
  const httpServer = {
    listen: jest.fn(),
    close: jest.fn((cb) => {
      if (cb) cb();
    }),
  };
  const WebSocketServer = jest.fn(function WebSocketServer(opts) {
    this.options = opts;
    this.handlers = new Map();
    this.on = jest.fn((event, handler) => {
      this.handlers.set(event, handler);
    });
    this.close = jest.fn((cb) => {
      if (cb) cb();
    });
  });
  const auth = {
    init: jest.fn(() => true),
    checkBearer: jest.fn(() => true),
  };
  const initializeDatabase = jest.fn().mockResolvedValue(undefined);
  const runMigrations = jest.fn().mockResolvedValue([]);
  const closeDatabase = jest.fn().mockResolvedValue(undefined);
  const recordTerminalConnection = jest.fn().mockResolvedValue({
    connectionId: 101,
    alias: 'alpha',
  });
  const touchTerminalHeartbeat = jest.fn().mockResolvedValue(undefined);
  const closeTerminalConnection = jest.fn().mockResolvedValue(undefined);
  const setDeviceAlias = jest.fn().mockResolvedValue(undefined);
  const setDeviceGroup = jest.fn().mockResolvedValue(undefined);
  const deleteDeviceAliasByGroupAndName = jest.fn().mockResolvedValue(false);
  const addBlockedRemote = jest.fn().mockResolvedValue(true);
  const getBlockedRemotes = jest.fn().mockResolvedValue([]);
  const appendBatchOutput = jest.fn((lines, entry, text) => lines.concat(`${entry.mac}:${text}`));
  const renderBatchOutput = jest.fn((lines) => lines.join('\n'));
  const loadLegacyAliases = jest.fn(() => ({}));
  const formatPromptOutput = jest.fn((text, mac) => `formatted:${mac}:${text}`);
  const parseListCommand = jest.fn(() => ({ type: 'unknown', raw: 'noop' }));
  const formatListCommandHelp = jest.fn(() => 'help');
  const formatShellExecution = jest.fn((command) => `shell ${command}`);
  const isAffirmativeResponse = jest.fn((value) => /^y/i.test(value));
  const executeLocalSessionCommand = jest.fn().mockResolvedValue(false);
  const createTerminalHttpHandler = jest.fn(() => jest.fn());
  const startSessionUpdate = jest.fn(() => false);
  const handleUpdateMessage = jest.fn();
  const sessionInput = {
    PASSTHROUGH_EXIT_HINT: 'Ctrl+]',
    PASSTHROUGH_EXIT_SEQUENCE: '\x1d',
    remoteInputForKeypress: jest.fn(() => null),
    shouldEnterPassthrough: jest.fn(() => false),
  };
  const terminalConfig = {
    host: '127.0.0.1',
    port: 8080,
    keyPath: '/tmp/ela.key',
  };

  Object.assign(auth, options.auth || {});
  if (options.db) {
    if (options.db.initializeDatabase) initializeDatabase.mockImplementation(options.db.initializeDatabase);
    if (options.db.runMigrations) runMigrations.mockImplementation(options.db.runMigrations);
    if (options.db.closeDatabase) closeDatabase.mockImplementation(options.db.closeDatabase);
  }
  if (options.registry) {
    if (options.registry.recordTerminalConnection) recordTerminalConnection.mockImplementation(options.registry.recordTerminalConnection);
    if (options.registry.touchTerminalHeartbeat) touchTerminalHeartbeat.mockImplementation(options.registry.touchTerminalHeartbeat);
    if (options.registry.closeTerminalConnection) closeTerminalConnection.mockImplementation(options.registry.closeTerminalConnection);
    if (options.registry.setDeviceAlias) setDeviceAlias.mockImplementation(options.registry.setDeviceAlias);
    if (options.registry.getBlockedRemotes) getBlockedRemotes.mockImplementation(options.registry.getBlockedRemotes);
  }
  if (options.formatPromptOutput) {
    formatPromptOutput.mockImplementation(options.formatPromptOutput);
  }
  if (options.loadLegacyAliases) {
    loadLegacyAliases.mockImplementation(options.loadLegacyAliases);
  }
  if (options.handleUpdateMessage) {
    handleUpdateMessage.mockImplementation(options.handleUpdateMessage);
  }
  if (options.startSessionUpdate) {
    startSessionUpdate.mockImplementation(options.startSessionUpdate);
  }
  if (options.appendBatchOutput) {
    appendBatchOutput.mockImplementation(options.appendBatchOutput);
  }
  const processOn = jest.spyOn(process, 'on').mockImplementation(() => process);
  jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  jest.spyOn(process, 'exit').mockImplementation(() => undefined);

  process.stdin.isTTY = false;
  process.stdin.setRawMode = jest.fn();
  process.stdin.on = jest.fn();

  jest.doMock('http', () => ({
    createServer: jest.fn(() => httpServer),
  }), { virtual: true });
  jest.doMock('readline', () => readlineMock, { virtual: true });
  jest.doMock('ws', () => ({ WebSocketServer }), { virtual: true });
  jest.doMock('../../../../api/auth', () => auth);
  jest.doMock('../../../../api/lib/config', () => ({
    getTerminalServiceConfig: jest.fn(() => terminalConfig),
  }));
  jest.doMock('../../../../api/lib/db', () => ({
    initializeDatabase,
    runMigrations,
    closeDatabase,
  }));
  const loadApiKeyHashes = jest.fn().mockResolvedValue([]);
  jest.doMock('../../../../api/lib/db/deviceRegistry', () => ({
    recordTerminalConnection,
    touchTerminalHeartbeat,
    closeTerminalConnection,
    setDeviceAlias,
    setDeviceGroup,
    deleteDeviceAliasByGroupAndName,
    addBlockedRemote,
    getBlockedRemotes,
    loadApiKeyHashes,
  }));
  jest.doMock('../../../../api/terminal/batchOutput', () => ({
    appendBatchOutput,
    renderBatchOutput,
  }));
  jest.doMock('../../../../api/terminal/legacyAliases', () => ({
    loadLegacyAliases,
  }));
  jest.doMock('../../../../api/terminal/promptFormatter', () => ({
    formatPromptOutput,
  }));
  jest.doMock('../../../../api/terminal/sessionRegistry', () => ({
    createSessionRegistry: jest.fn(() => sessionRegistry),
  }));
  jest.doMock('../../../../api/terminal/listCommands', () => ({
    formatListCommandHelp,
    formatShellExecution,
    isAffirmativeResponse,
    parseListCommand,
  }));
  jest.doMock('../../../../api/terminal/localCommands', () => ({
    executeLocalSessionCommand,
  }));
  jest.doMock('../../../../api/terminal/httpRoutes', () => ({
    createTerminalHttpHandler,
  }));
  jest.doMock('../../../../api/terminal/updateManager', () => ({
    startSessionUpdate,
    handleUpdateMessage,
  }));
  jest.doMock('../../../../api/terminal/sessionInput', () => sessionInput);

  const server = require('../../../../api/terminal/server');

  return {
    server,
    sessionRegistry,
    readlineMock,
    httpServer,
    WebSocketServer,
    wssClose: server.wss.close,
    auth,
    initializeDatabase,
    runMigrations,
    closeDatabase,
    recordTerminalConnection,
    touchTerminalHeartbeat,
    closeTerminalConnection,
    setDeviceAlias,
    appendBatchOutput,
    renderBatchOutput,
    loadLegacyAliases,
    formatPromptOutput,
    parseListCommand,
    formatListCommandHelp,
    formatShellExecution,
    executeLocalSessionCommand,
    handleUpdateMessage,
    startSessionUpdate,
    shouldEnterPassthrough: sessionInput.shouldEnterPassthrough,
    remoteInputForKeypress: sessionInput.remoteInputForKeypress,
    processOn,
  };
}

describe('terminal server orchestration', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('verifyClient enforces terminal path and bearer auth', () => {
    const { server, auth } = loadTerminalServer();
    const verifyClient = server.wss.options.verifyClient;
    const done = jest.fn();

    verifyClient({ req: { url: '/wrong', headers: {} } }, done);
    expect(done).toHaveBeenCalledWith(false, 404, 'Not Found');

    auth.checkBearer.mockReturnValueOnce(false);
    verifyClient({ req: { url: '/terminal/aa:bb', headers: { authorization: 'Bearer nope' } } }, done);
    expect(done).toHaveBeenCalledWith(false, 401, 'Unauthorized');

    auth.checkBearer.mockReturnValueOnce(true);
    verifyClient({ req: { url: '/terminal/aa:bb', headers: { authorization: 'Bearer ok' } } }, done);
    expect(done).toHaveBeenCalledWith(true);
  });

  test('verifyClient stores the authenticated username on req when a key is matched', () => {
    const { server, auth } = loadTerminalServer();
    const verifyClient = server.wss.options.verifyClient;
    const done = jest.fn();

    auth.checkBearer.mockReturnValueOnce('alice');
    const req = { url: '/terminal/aa:bb', headers: { authorization: 'Bearer ok' } };
    verifyClient({ req }, done);
    expect(done).toHaveBeenCalledWith(true);
    expect(req.authenticatedUser).toBe('alice');
  });

  test('verifyClient rejects missing auth, malformed auth, and empty terminal mac paths', () => {
    const { server, auth } = loadTerminalServer();
    const verifyClient = server.wss.options.verifyClient;
    const done = jest.fn();

    auth.checkBearer.mockReturnValueOnce(false);
    verifyClient({ req: { url: '/terminal/aa:bb', headers: {} } }, done);
    expect(done).toHaveBeenCalledWith(false, 401, 'Unauthorized');

    auth.checkBearer.mockReturnValueOnce(false);
    verifyClient({ req: { url: '/terminal/aa:bb', headers: { authorization: 'Basic nope' } } }, done);
    expect(done).toHaveBeenCalledWith(false, 401, 'Unauthorized');

    verifyClient({ req: { url: '/terminal/', headers: { authorization: 'Bearer ok' } } }, done);
    expect(done).toHaveBeenCalledWith(false, 404, 'Not Found');
  });

  test('connection handler passes authenticatedUser to recordTerminalConnection', async () => {
    const { server, recordTerminalConnection } = loadTerminalServer();
    const onConnection = server.wss.handlers.get('connection');
    const ws = createFakeWs();

    await onConnection(ws, {
      url: '/terminal/aa:bb',
      socket: { remoteAddress: '10.0.0.1' },
      authenticatedUser: 'alice',
    });

    expect(recordTerminalConnection).toHaveBeenCalledWith('aa:bb', '10.0.0.1', 'alice');
  });

  test('replaces an existing session when the same MAC reconnects', async () => {
    const { server, sessionRegistry, recordTerminalConnection } = loadTerminalServer();
    const onConnection = server.wss.handlers.get('connection');
    const firstWs = createFakeWs();
    const secondWs = createFakeWs();

    await onConnection(firstWs, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.1' } });
    expect(sessionRegistry.getSession('aa:bb')).toBeTruthy();

    recordTerminalConnection.mockResolvedValueOnce({ connectionId: 202, alias: 'beta' });
    await onConnection(secondWs, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.2' } });

    expect(firstWs.close).toHaveBeenCalledTimes(1);
    expect(sessionRegistry.getSession('aa:bb').ws).toBe(secondWs);
    expect(sessionRegistry.getSession('aa:bb').connectionId).toBe(202);
  });

  test('replaces an existing session even when the previous socket throws during close', async () => {
    const { server, sessionRegistry } = loadTerminalServer();
    const onConnection = server.wss.handlers.get('connection');
    const firstWs = createFakeWs();
    const secondWs = createFakeWs();
    firstWs.close.mockImplementationOnce(() => {
      throw new Error('socket already closed');
    });

    await onConnection(firstWs, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.1' } });
    await onConnection(secondWs, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.2' } });

    expect(process.stderr.write).toHaveBeenCalledWith('Warning: failed to close existing terminal session for aa:bb: socket already closed\n');
    expect(sessionRegistry.getSession('aa:bb').ws).toBe(secondWs);
  });

  test('closes the socket with code 1011 when terminal registration fails', async () => {
    const { server } = loadTerminalServer({
      registry: {
        recordTerminalConnection: async () => {
          throw new Error('db down');
        },
      },
    });
    const onConnection = server.wss.handlers.get('connection');
    const ws = createFakeWs();

    await onConnection(ws, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.1' } });

    expect(ws.close).toHaveBeenCalledWith(1011, 'database unavailable');
    expect(process.stderr.write).toHaveBeenCalledWith(expect.stringContaining('Failed to register terminal connection for aa:bb: db down'));
  });

  test('parses heartbeat acknowledgements and touches the connection heartbeat', async () => {
    const { server, sessionRegistry, touchTerminalHeartbeat } = loadTerminalServer();
    const onConnection = server.wss.handlers.get('connection');
    const ws = createFakeWs();

    await onConnection(ws, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.1' } });
    const entry = sessionRegistry.getSession('aa:bb');

    ws.handlers.get('message')(Buffer.from('{"_type":"heartbeat_ack","date":"2026-03-19T12:34:56.000Z"}'));

    expect(entry.lastHeartbeat).toBe('2026-03-19T12:34:56.000Z');
    expect(touchTerminalHeartbeat).toHaveBeenCalledWith(101, new Date('2026-03-19T12:34:56.000Z'));
  });

  test('treats invalid JSON and non-heartbeat JSON payloads as normal buffered output', async () => {
    const { server, sessionRegistry, handleUpdateMessage, formatPromptOutput } = loadTerminalServer();
    const onConnection = server.wss.handlers.get('connection');
    const ws = createFakeWs();

    server.tui.state = server.TUI_STATE.SESSION_LIST;
    await onConnection(ws, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.1' } });
    const entry = sessionRegistry.getSession('aa:bb');

    ws.handlers.get('message')(Buffer.from('{"broken":'));
    ws.handlers.get('message')(Buffer.from('{"_type":"status","value":"ok"}'));

    expect(formatPromptOutput).toHaveBeenCalledWith('{"broken":', 'aa:bb');
    expect(formatPromptOutput).toHaveBeenCalledWith('{"_type":"status","value":"ok"}', 'aa:bb');
    expect(handleUpdateMessage).toHaveBeenCalledWith(entry, '{"broken":', expect.any(Object));
    expect(handleUpdateMessage).toHaveBeenCalledWith(entry, '{"_type":"status","value":"ok"}', expect.any(Object));
    expect(entry.outputBuffer).toEqual([
      'formatted:aa:bb:{"broken":',
      'formatted:aa:bb:{"_type":"status","value":"ok"}',
    ]);
  });

  test('heartbeat ack failure logging does not render or buffer output for non-active sessions', async () => {
    const { server, sessionRegistry, touchTerminalHeartbeat } = loadTerminalServer({
      registry: {
        touchTerminalHeartbeat: async () => {
          throw new Error('hb write failed');
        },
      },
    });
    const onConnection = server.wss.handlers.get('connection');
    const ws = createFakeWs();
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    server.tui.state = server.TUI_STATE.SESSION_LIST;
    await onConnection(ws, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.1' } });
    const entry = sessionRegistry.getSession('aa:bb');

    ws.handlers.get('message')(Buffer.from('{"_type":"heartbeat_ack","date":"2026-03-19T13:00:00.000Z"}'));
    await flush();

    expect(entry.lastHeartbeat).toBe('2026-03-19T13:00:00.000Z');
    expect(entry.outputBuffer).toEqual([]);
    expect(server.tui.render).toHaveBeenCalledTimes(1);
    expect(process.stdout.write).not.toHaveBeenCalledWith(expect.stringContaining('heartbeat_ack'));
    expect(touchTerminalHeartbeat).toHaveBeenCalledWith(101, new Date('2026-03-19T13:00:00.000Z'));
    expect(process.stderr.write).toHaveBeenCalledWith('Warning: failed to update heartbeat for aa:bb: hb write failed\n');
  });

  test('buffers non-json output and updates batch output in session-list mode', async () => {
    const { server, sessionRegistry, appendBatchOutput, formatPromptOutput, handleUpdateMessage } = loadTerminalServer();
    const onConnection = server.wss.handlers.get('connection');
    const ws = createFakeWs();

    server.tui.state = server.TUI_STATE.SESSION_LIST;
    server.tui._batchOutputActive = true;
    server.tui._batchOutputLines = ['existing'];
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    await onConnection(ws, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.1' } });
    const entry = sessionRegistry.getSession('aa:bb');

    ws.handlers.get('message')(Buffer.from('raw output'));

    expect(formatPromptOutput).toHaveBeenCalledWith('raw output', 'aa:bb');
    expect(handleUpdateMessage).toHaveBeenCalledWith(entry, 'raw output', expect.any(Object));
    expect(entry.outputBuffer).toEqual(['formatted:aa:bb:raw output']);
    expect(appendBatchOutput).toHaveBeenCalledWith(['existing'], entry, 'formatted:aa:bb:raw output');
    expect(server.tui.render).toHaveBeenCalled();
  });

  test('writes prompt output directly for the active attached session', async () => {
    const { server } = loadTerminalServer();
    const onConnection = server.wss.handlers.get('connection');
    const ws = createFakeWs();

    server.tui.state = server.TUI_STATE.ACTIVE_SESSION;
    server.tui.activeMac = 'aa:bb';

    await onConnection(ws, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.1' } });
    ws.handlers.get('message')(Buffer.from('hello'));

    expect(process.stdout.write).toHaveBeenCalledWith('formatted:aa:bb:hello');
  });

  test('routes update-state transitions to stdout for the active session and re-render for the session list', async () => {
    const { server } = loadTerminalServer({
      handleUpdateMessage: (entry, _rawText, callbacks) => {
        entry.updateError = 'network failed';
        callbacks.onUpdateFailed(entry);
      },
    });
    const onConnection = server.wss.handlers.get('connection');
    const ws = createFakeWs();

    server.tui.state = server.TUI_STATE.ACTIVE_SESSION;
    server.tui.activeMac = 'aa:bb';
    await onConnection(ws, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.1' } });
    ws.handlers.get('message')(Buffer.from('update text'));
    expect(process.stdout.write).toHaveBeenCalledWith('\r\n[update failed: network failed]\r\n');

    server.tui.state = server.TUI_STATE.SESSION_LIST;
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});
    ws.handlers.get('message')(Buffer.from('update text'));
    expect(server.tui.render).toHaveBeenCalled();
  });

  test('close and error handlers clean up sessions and detach the active session', async () => {
    const { server, sessionRegistry, closeTerminalConnection } = loadTerminalServer();
    const onConnection = server.wss.handlers.get('connection');
    const ws = createFakeWs();

    await onConnection(ws, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.1' } });
    expect(sessionRegistry.getSession('aa:bb')).toBeTruthy();

    server.tui.state = server.TUI_STATE.ACTIVE_SESSION;
    server.tui.activeMac = 'aa:bb';
    jest.spyOn(server.tui, 'detach').mockImplementation(() => {});

    ws.handlers.get('close')();
    await flush();

    expect(closeTerminalConnection).toHaveBeenCalledWith(101);
    expect(process.stdout.write).toHaveBeenCalledWith('\r\n[session disconnected]\r\n');
    expect(server.tui.detach).toHaveBeenCalled();
    expect(sessionRegistry.getSession('aa:bb')).toBeUndefined();

    await onConnection(ws, { url: '/terminal/cc:dd', socket: { remoteAddress: '10.0.0.2' } });
    expect(sessionRegistry.getSession('cc:dd')).toBeTruthy();
    ws.handlers.get('error')();
    expect(sessionRegistry.getSession('cc:dd')).toBeUndefined();
  });

  test('close and error handlers tolerate unknown sessions and close-terminal rejection', async () => {
    const { server, sessionRegistry, closeTerminalConnection } = loadTerminalServer({
      registry: {
        closeTerminalConnection: async () => {
          throw new Error('close failed');
        },
      },
    });
    const onConnection = server.wss.handlers.get('connection');
    const ws = createFakeWs();
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    server.tui.state = server.TUI_STATE.SESSION_LIST;
    await onConnection(ws, { url: '/terminal/aa:bb', socket: { remoteAddress: '10.0.0.1' } });

    sessionRegistry.removeSession('aa:bb');
    expect(() => ws.handlers.get('close')()).not.toThrow();
    await flush();
    expect(closeTerminalConnection).toHaveBeenCalledWith(101);
    expect(process.stderr.write).toHaveBeenCalledWith('Warning: failed to close terminal connection for aa:bb: close failed\n');

    expect(() => ws.handlers.get('error')()).not.toThrow();
  });

  test('importLegacyAliases imports non-empty aliases and logs partial failures', async () => {
    const { server, setDeviceAlias, loadLegacyAliases } = loadTerminalServer({
      loadLegacyAliases: () => ({
        'aa:bb': 'router',
        'cc:dd': '',
        'ee:ff': 'broken',
      }),
      registry: {
        setDeviceAlias: async (mac) => {
          if (mac === 'ee:ff') {
            throw new Error('save failed');
          }
        },
      },
    });

    await server.importLegacyAliases();

    expect(loadLegacyAliases).toHaveBeenCalledWith(server.LEGACY_ALIASES_FILE);
    expect(setDeviceAlias).toHaveBeenCalledWith('aa:bb', 'router', 'legacy_terminal_file');
    expect(setDeviceAlias).toHaveBeenCalledWith('ee:ff', 'broken', 'legacy_terminal_file');
    expect(setDeviceAlias).not.toHaveBeenCalledWith('cc:dd', '', 'legacy_terminal_file');
    expect(process.stderr.write).toHaveBeenCalledWith('Warning: failed to import alias for ee:ff: save failed\n');
  });

  test('cleanup closes tracked DB connections, clears tty raw mode, and exitGracefully exits after DB shutdown', async () => {
    const { server, sessionRegistry, closeDatabase, closeTerminalConnection } = loadTerminalServer();
    const ws = createFakeWs();
    sessionRegistry.addSession('aa:bb', ws, { alias: 'router', connectionId: 12 });
    process.stdin.isTTY = true;

    await server.cleanup();

    expect(closeTerminalConnection).toHaveBeenCalledWith(12);
    expect(process.stdin.setRawMode).toHaveBeenCalledWith(false);
    expect(process.stdout.write).toHaveBeenCalledWith(`${server.ANSI.reset}\r\n`);
    expect(sessionRegistry.size).toBe(0);

    sessionRegistry.addSession('bb:cc', ws, { connectionId: 44 });
    server.exitGracefully();
    await flush();
    await flush();

    expect(closeTerminalConnection).toHaveBeenCalledWith(44);
    expect(closeDatabase).toHaveBeenCalled();
    expect(process.exit).toHaveBeenCalledWith(0);
  });

  test('attach flushes buffered output and detach returns to the session list', () => {
    const { server, sessionRegistry } = loadTerminalServer();
    const ws = createFakeWs();
    const entry = sessionRegistry.addSession('aa:bb', ws, { alias: 'router' });
    entry.outputBuffer = ['line1\r\n', 'line2\r\n'];
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    server.tui.attach('aa:bb');

    expect(server.tui.state).toBe(server.TUI_STATE.ACTIVE_SESSION);
    expect(server.tui.activeMac).toBe('aa:bb');
    expect(process.stdout.write).toHaveBeenCalledWith(server.ANSI.clear);
    expect(process.stdout.write).toHaveBeenCalledWith(expect.stringContaining('Attached to router (aa:bb)'));
    expect(process.stdout.write).toHaveBeenCalledWith('line1\r\nline2\r\n');
    expect(entry.outputBuffer).toEqual([]);

    entry.inputMode = 'passthrough';
    server.tui.detach();

    expect(server.tui.state).toBe(server.TUI_STATE.SESSION_LIST);
    expect(server.tui.activeMac).toBeNull();
    expect(entry.inputMode).toBe('line');
    expect(server.tui.render).toHaveBeenCalled();
  });

  test('render shows the exact empty-state view and resets cursor after session list shrink', () => {
    const { server, sessionRegistry } = loadTerminalServer();

    server.tui.cursor = 4;
    server.tui.render();
    expect(process.stdout.write).toHaveBeenCalledWith(
      expect.stringContaining('ela-terminal'),
    );
    expect(process.stdout.write).toHaveBeenCalledWith(
      expect.stringContaining('  (no connected devices)'),
    );

    sessionRegistry.addSession('aa:bb', createFakeWs(), {});
    sessionRegistry.addSession('bb:cc', createFakeWs(), {});
    server.tui.cursor = 1;
    sessionRegistry.removeSession('bb:cc');
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    server.tui.detach();

    expect(server.tui.cursor).toBe(0);
  });

  test('render includes alias, raw mac, and heartbeat details in the session list and attach header', () => {
    const { server, sessionRegistry } = loadTerminalServer();
    const aliased = sessionRegistry.addSession('aa:bb', createFakeWs(), { alias: 'router' });
    const plain = sessionRegistry.addSession('cc:dd', createFakeWs(), {});
    aliased.lastHeartbeat = '2026-03-19T14:00:00.000Z';
    plain.lastHeartbeat = null;

    server.tui.cursor = 0;
    server.tui.render();

    expect(process.stdout.write).toHaveBeenCalledWith(expect.stringContaining('router (aa:bb)  last heartbeat: 2026-03-19T14:00:00.000Z'));
    expect(process.stdout.write).toHaveBeenCalledWith(expect.stringContaining('  cc:dd'));

    process.stdout.write.mockClear();
    server.tui.attach('aa:bb');
    expect(process.stdout.write).toHaveBeenCalledWith(expect.stringContaining('Attached to router (aa:bb)'));

    process.stdout.write.mockClear();
    server.tui.detach();
    server.tui.attach('cc:dd');
    expect(process.stdout.write).toHaveBeenCalledWith(expect.stringContaining('Attached to cc:dd'));
  });

  test('list-mode key handling navigates sessions and opens command mode', () => {
    const { server, sessionRegistry } = loadTerminalServer();
    sessionRegistry.addSession('aa:bb', createFakeWs(), {});
    sessionRegistry.addSession('bb:cc', createFakeWs(), {});
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});
    jest.spyOn(server.tui, 'attach').mockImplementation(() => {});

    server.tui.cursor = 0;
    server.tui.handleKey('', 'down', false);
    expect(server.tui.cursor).toBe(1);

    server.tui.handleKey('', 'up', false);
    expect(server.tui.cursor).toBe(0);

    server.tui.handleKey('/', undefined, false);
    expect(server.tui._listCmd).toBe('');

    server.tui._listCmd = null;
    server.tui.handleKey('', 'return', false);
    expect(server.tui.attach).toHaveBeenCalledWith('aa:bb');
  });

  test('list command help and invalid commands update status messages', () => {
    const { server, parseListCommand, formatListCommandHelp } = loadTerminalServer();
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    parseListCommand.mockReturnValueOnce({ type: 'help' });
    server.tui._executeListCommand('help');
    expect(server.tui._statusMsg).toBe('help');
    expect(formatListCommandHelp).toHaveBeenCalled();

    parseListCommand.mockReturnValueOnce({ type: 'invalid-shell' });
    server.tui._executeListCommand('shell');
    expect(server.tui._statusMsg).toBe('usage: /shell <command>');

    parseListCommand.mockReturnValueOnce({ type: 'invalid-cmd' });
    server.tui._executeListCommand('cmd');
    expect(server.tui._statusMsg).toBe('usage: /cmd <command>');

    parseListCommand.mockReturnValueOnce({ type: 'invalid-set' });
    server.tui._executeListCommand('set');
    expect(server.tui._statusMsg).toBe('usage: /set <key> <value>');

    parseListCommand.mockReturnValueOnce({ type: 'unknown', raw: 'weird' });
    server.tui._executeListCommand('weird');
    expect(server.tui._statusMsg).toBe('unknown command: /weird');
  });

  test('list command edge cases handle empty lists and unopened sockets cleanly', () => {
    const { server, sessionRegistry, parseListCommand, startSessionUpdate } = loadTerminalServer({
      startSessionUpdate: () => false,
    });
    const closedWs = createFakeWs();
    closedWs.readyState = 0;
    sessionRegistry.addSession('aa:bb', closedWs, {});
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    parseListCommand.mockReturnValueOnce({ type: 'update' });
    server.tui._executeListCommand('update');
    expect(startSessionUpdate).toHaveBeenCalledTimes(1);
    expect(server.tui._statusMsg).toBe('update: initiated for 0 session(s)');

    parseListCommand.mockReturnValueOnce({ type: 'shell-all', command: 'uname -a' });
    server.tui._executeListCommand('shell uname -a');
    server.tui._confirmAction();
    expect(server.tui._statusMsg).toBe('shell: launched on 0 node(s)');

    parseListCommand.mockReturnValueOnce({ type: 'set-all', key: 'FOO', value: 'bar' });
    server.tui._executeListCommand('set FOO bar');
    server.tui._confirmAction();
    expect(server.tui._statusMsg).toBe('set: dispatched "FOO" to 0 node(s)');
  });

  test('list command confirm flows dispatch update, shell-all, exit, and set-all actions', () => {
    const { server, sessionRegistry, parseListCommand, startSessionUpdate, formatShellExecution } = loadTerminalServer({
      startSessionUpdate: () => true,
    });
    const ws1 = createFakeWs();
    const ws2 = createFakeWs();
    sessionRegistry.addSession('aa:bb', ws1, {});
    sessionRegistry.addSession('bb:cc', ws2, {});
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    parseListCommand.mockReturnValueOnce({ type: 'update' });
    server.tui._executeListCommand('update');
    expect(startSessionUpdate).toHaveBeenCalledTimes(2);
    expect(server.tui._statusMsg).toBe('update: initiated for 2 session(s)');

    parseListCommand.mockReturnValueOnce({ type: 'shell-all', command: 'uname -a' });
    server.tui._executeListCommand('shell uname -a');
    expect(server.tui._confirmPrompt).toContain('shell uname -a');
    server.tui._confirmAction();
    expect(ws1.send).toHaveBeenCalledWith('shell uname -a\n');
    expect(ws2.send).toHaveBeenCalledWith('shell uname -a\n');
    expect(formatShellExecution).toHaveBeenCalledWith('uname -a');
    expect(server.tui._batchOutputActive).toBe(true);

    parseListCommand.mockReturnValueOnce({ type: 'exit' });
    server.tui._executeListCommand('exit');
    server.tui._confirmAction();
    expect(ws1.send).toHaveBeenCalledWith('exit\n');
    expect(ws2.send).toHaveBeenCalledWith('exit\n');

    parseListCommand.mockReturnValueOnce({ type: 'set-all', key: 'FOO', value: 'bar' });
    server.tui._executeListCommand('set FOO bar');
    server.tui._confirmAction();
    expect(ws1.send).toHaveBeenCalledWith('\x15');
    expect(ws1.send).toHaveBeenCalledWith('set FOO bar\n');
    expect(ws2.send).toHaveBeenCalledWith('\x15');
    expect(ws2.send).toHaveBeenCalledWith('set FOO bar\n');
  });

  test('confirm prompt input accepts, cancels, and edits values', () => {
    const { server } = loadTerminalServer();
    const action = jest.fn();
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    server.tui._confirmPrompt = '[confirm]';
    server.tui._confirmValue = '';
    server.tui._confirmAction = action;

    server.tui.handleKey('y', undefined, false);
    expect(server.tui._confirmValue).toBe('y');

    server.tui.handleKey('', 'backspace', false);
    expect(server.tui._confirmValue).toBe('');

    server.tui.handleKey('y', undefined, false);
    server.tui.handleKey('', 'return', false);
    expect(action).toHaveBeenCalledTimes(1);

    server.tui._confirmPrompt = '[confirm]';
    server.tui._confirmValue = '';
    server.tui._confirmAction = jest.fn();
    server.tui.handleKey('', 'escape', false);
    expect(server.tui._confirmPrompt).toBeNull();
    expect(process.stdout.write).toHaveBeenCalledWith('\r\n[cancelled]\r\n');
  });

  test('confirm prompts accept uppercase answers, cancel empty answers, and ignore repeated backspace at column zero', () => {
    const { server } = loadTerminalServer();
    const action = jest.fn();
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    server.tui._confirmPrompt = '[confirm]';
    server.tui._confirmValue = '';
    server.tui._confirmAction = action;
    server.tui.handleKey('', 'backspace', false);
    server.tui.handleKey('', 'backspace', false);
    expect(server.tui._confirmValue).toBe('');

    server.tui.handleKey('Y', undefined, false);
    server.tui.handleKey('', 'return', false);
    expect(action).toHaveBeenCalledTimes(1);

    server.tui._confirmPrompt = '[confirm]';
    server.tui._confirmValue = '';
    server.tui._confirmAction = jest.fn();
    process.stdout.write.mockClear();
    server.tui.handleKey('', 'return', false);
    expect(process.stdout.write).toHaveBeenCalledWith('\r\n[cancelled]\r\n');
  });

  test('session key handling executes local commands, enters passthrough, and relays keys', async () => {
    const { server, sessionRegistry, executeLocalSessionCommand, shouldEnterPassthrough, setDeviceAlias } = loadTerminalServer();
    const ws = createFakeWs();
    const entry = sessionRegistry.addSession('aa:bb', ws, {});
    server.tui.state = server.TUI_STATE.ACTIVE_SESSION;
    server.tui.activeMac = 'aa:bb';
    server.tui.detach = jest.fn();

    executeLocalSessionCommand.mockResolvedValueOnce(false);
    shouldEnterPassthrough.mockReturnValueOnce(true);
    server.tui._localCmdBuf = 'remote run';
    await server.tui._handleSessionKey('', 'return', false);

    expect(executeLocalSessionCommand).toHaveBeenCalledWith(expect.objectContaining({
      cmd: 'remote run',
      activeMac: 'aa:bb',
      sessionEntry: entry,
      setDeviceAlias,
    }));
    expect(entry.inputMode).toBe('passthrough');
    expect(ws.send).toHaveBeenCalledWith('\n');

    entry.inputMode = 'line';
    ws.send.mockClear();
    server.tui._localCmdBuf = '';
    server.tui.handleKey('a', undefined, false);
    expect(ws.send).toHaveBeenCalledWith('a');

    server.tui.handleKey('', 'backspace', false);
    expect(ws.send).toHaveBeenCalledWith('\x7f');
  });

  test('attached-session unknown slash commands fall through to remote input without crashing', async () => {
    const { server, sessionRegistry, executeLocalSessionCommand } = loadTerminalServer();
    const ws = createFakeWs();
    sessionRegistry.addSession('aa:bb', ws, {});
    server.tui.state = server.TUI_STATE.ACTIVE_SESSION;
    server.tui.activeMac = 'aa:bb';
    server.tui._localCmdBuf = '/weird';

    executeLocalSessionCommand.mockResolvedValueOnce(false);
    await server.tui._handleSessionKey('', 'return', false);

    expect(executeLocalSessionCommand).toHaveBeenCalledWith(expect.objectContaining({ cmd: '/weird' }));
    expect(ws.send).toHaveBeenCalledWith('\n');
    expect(server.tui._localCmdBuf).toBe('');
  });

  test('passthrough and local-command error handling write user-facing messages', async () => {
    const { server, sessionRegistry, executeLocalSessionCommand, remoteInputForKeypress } = loadTerminalServer();
    const ws = createFakeWs();
    const entry = sessionRegistry.addSession('aa:bb', ws, {});
    server.tui.state = server.TUI_STATE.ACTIVE_SESSION;
    server.tui.activeMac = 'aa:bb';

    entry.inputMode = 'passthrough';
    remoteInputForKeypress.mockReturnValueOnce('\x1b[A');
    server.tui.handleKey('', 'up', false);
    expect(ws.send).toHaveBeenCalledWith('\x1b[A');

    server.tui.handleKey(server.sessionInput ? server.sessionInput.PASSTHROUGH_EXIT_SEQUENCE : '\x1d', undefined, false);
    expect(entry.inputMode).toBe('line');
    expect(process.stdout.write).toHaveBeenCalledWith("\r\n[passthrough mode disabled; '/detach' is available again]\r\n");

    executeLocalSessionCommand.mockRejectedValueOnce(new Error('alias save failed'));
    server.tui._localCmdBuf = 'alias new-name';
    await server.tui._handleSessionKey('', 'return', false);
    expect(process.stdout.write).toHaveBeenCalledWith('\r\n[failed to save: alias save failed]\r\n');
  });

  test('setupInput warns when stdin is not a TTY', () => {
    const { server, readlineMock } = loadTerminalServer();
    process.stdin.isTTY = false;

    server.setupInput();

    expect(process.stderr.write).toHaveBeenCalledWith('Warning: stdin is not a TTY; interactive TUI unavailable.\n');
    expect(readlineMock.emitKeypressEvents).not.toHaveBeenCalled();
    expect(process.stdin.setRawMode).not.toHaveBeenCalled();
    expect(process.stdin.on).not.toHaveBeenCalled();
  });

  test('setupInput enables raw mode and forwards keypresses to the TUI when stdin is a TTY', () => {
    const { server, readlineMock } = loadTerminalServer();
    process.stdin.isTTY = true;
    const handleKeySpy = jest.spyOn(server.tui, 'handleKey').mockImplementation(() => {});

    server.setupInput();

    expect(readlineMock.emitKeypressEvents).toHaveBeenCalledWith(process.stdin);
    expect(process.stdin.setRawMode).toHaveBeenCalledWith(true);
    expect(process.stdin.on).toHaveBeenCalledWith('keypress', expect.any(Function));

    const keypressHandler = process.stdin.on.mock.calls[0][1];
    keypressHandler('a', { name: 'a', ctrl: false });
    expect(handleKeySpy).toHaveBeenCalledWith('a', 'a', false);
  });

  test('registers SIGINT and SIGTERM handlers at module load', () => {
    const { processOn } = loadTerminalServer();

    expect(processOn).toHaveBeenCalledWith('SIGINT', expect.any(Function));
    expect(processOn).toHaveBeenCalledWith('SIGTERM', expect.any(Function));
  });

  test('main exits when validate-key auth initialization fails', async () => {
    const { server, auth, initializeDatabase } = loadTerminalServer({
      auth: {
        init: jest.fn(() => false),
      },
    });
    auth.init.mockImplementation(() => false);

    await server.main();

    expect(process.stderr.write).toHaveBeenCalledWith('error: --validate-key is set but no API keys are configured in the database\n');
    expect(process.exit).toHaveBeenCalledWith(1);
    expect(initializeDatabase).toHaveBeenCalledTimes(1);
  });

  test('main starts the HTTP server end-to-end and renders the TUI after listen callback', async () => {
    const { server, auth, initializeDatabase, runMigrations, loadLegacyAliases, httpServer, readlineMock } = loadTerminalServer();
    process.stdin.isTTY = true;
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    await server.main();

    expect(auth.init).toHaveBeenCalledWith(false, expect.any(Function));
    expect(initializeDatabase).toHaveBeenCalledTimes(1);
    expect(runMigrations).toHaveBeenCalledTimes(1);
    expect(loadLegacyAliases).toHaveBeenCalledWith(server.LEGACY_ALIASES_FILE);
    expect(httpServer.listen).toHaveBeenCalledWith(8080, '127.0.0.1', expect.any(Function));

    const listenCallback = httpServer.listen.mock.calls[0][2];
    listenCallback();

    expect(readlineMock.emitKeypressEvents).toHaveBeenCalledWith(process.stdin);
    expect(process.stdin.setRawMode).toHaveBeenCalledWith(true);
    expect(process.stdout.write).toHaveBeenCalledWith('ELA terminal API listening on ws://127.0.0.1:8080\n');
    expect(server.tui.render).toHaveBeenCalledTimes(1);
  });

  test('listen callback surfaces setupInput failures directly', async () => {
    const { server, httpServer } = loadTerminalServer();
    process.stdin.isTTY = true;
    process.stdin.setRawMode.mockImplementationOnce(() => {
      throw new Error('tty unavailable');
    });

    await server.main();

    const listenCallback = httpServer.listen.mock.calls[0][2];
    expect(() => listenCallback()).toThrow('tty unavailable');
  });

  test('cleanup ignores websocket/http server close failures and exitGracefully tolerates raw-mode errors', async () => {
    const { server, sessionRegistry, httpServer, wssClose, closeDatabase } = loadTerminalServer();
    process.stdin.isTTY = true;
    process.stdin.setRawMode.mockImplementation(() => {
      throw new Error('tty reset failed');
    });
    httpServer.close.mockImplementationOnce(() => {
      throw new Error('http close failed');
    });
    wssClose.mockImplementationOnce(() => {
      throw new Error('ws close failed');
    });
    sessionRegistry.addSession('aa:bb', createFakeWs(), { connectionId: 77 });

    await expect(server.cleanup()).resolves.toBeUndefined();
    expect(process.stdout.write).toHaveBeenCalledWith(`${server.ANSI.reset}\r\n`);

    process.stdout.write.mockClear();
    server.exitGracefully();
    await flush();
    await flush();
    expect(closeDatabase).toHaveBeenCalled();
    expect(process.exit).toHaveBeenCalledWith(0);
  });

  test('main propagates startup failures and start() logs, closes DB, and exits', async () => {
    const failure = new Error('legacy alias load failed');
    const { server, closeDatabase } = loadTerminalServer({
      loadLegacyAliases: () => {
        throw failure;
      },
    });

    await server.start();

    expect(process.stderr.write).toHaveBeenCalledWith(expect.stringContaining('legacy alias load failed'));
    expect(closeDatabase).toHaveBeenCalledTimes(1);
    expect(process.exit).toHaveBeenCalledWith(1);
  });

  test('verifyClient rejects connections from blocked IPs with 403', () => {
    const { server } = loadTerminalServer();
    const verifyClient = server.wss.options.verifyClient;
    const done = jest.fn();

    server.blockedCidrs.push({ network: (10 << 24) | 1, mask: 0xffffffff, cidr: '10.0.0.1/32' });

    verifyClient({ req: { url: '/terminal/aa:bb', headers: { authorization: 'Bearer ok' }, socket: { remoteAddress: '10.0.0.1' } } }, done);
    expect(done).toHaveBeenCalledWith(false, 403, 'Forbidden');

    done.mockClear();
    verifyClient({ req: { url: '/terminal/aa:bb', headers: { authorization: 'Bearer ok' }, socket: { remoteAddress: '10.0.0.2' } } }, done);
    expect(done).toHaveBeenCalledWith(true);
  });

  test('main() loads the block list from the database on startup', async () => {
    const { server } = loadTerminalServer({
      registry: {
        getBlockedRemotes: async () => [{ cidr: '10.0.0.0/8' }],
      },
    });
    jest.spyOn(server.tui, 'render').mockImplementation(() => {});

    await server.main();

    expect(server.blockedCidrs.length).toBe(1);
    expect(server.blockedCidrs[0].cidr).toBe('10.0.0.0/8');
  });
});
