'use strict';

function loadGdbServer(options = {}) {
  jest.resetModules();

  const agentKeys = options.agentKeys || [];
  const clientKeys = options.clientKeys || [];

  const httpServer = {
    listen: jest.fn((_port, _host, cb) => cb && cb()),
    close: jest.fn((cb) => cb && cb()),
  };
  const WebSocketServer = jest.fn(function WebSocketServer(opts) {
    this.options = opts;
    this.handlers = new Map();
    this.on = jest.fn((event, handler) => {
      this.handlers.set(event, handler);
    });
  });
  const auth = {
    matchBearer: jest.fn(() => null),
  };
  const initializeDatabase = jest.fn().mockResolvedValue(undefined);
  const runMigrations = jest.fn().mockResolvedValue([]);
  const closeDatabase = jest.fn().mockResolvedValue(undefined);
  const loadApiKeyHashes = jest.fn((scope) => Promise.resolve(scope === 'client' ? clientKeys : agentKeys));
  const parseGdbUrl = jest.fn(() => null);
  const sm = {
    sessions: new Map(),
    getOrCreate: jest.fn(),
    relay: jest.fn(),
    purge: jest.fn(),
    keys: jest.fn(() => []),
  };

  if (options.auth) Object.assign(auth, options.auth);
  if (options.db) {
    if (options.db.initializeDatabase) initializeDatabase.mockImplementation(options.db.initializeDatabase);
    if (options.db.runMigrations) runMigrations.mockImplementation(options.db.runMigrations);
  }

  const processOn = jest.spyOn(process, 'on').mockImplementation(() => process);
  jest.spyOn(process, 'exit').mockImplementation(() => undefined);
  jest.spyOn(process.stderr, 'write').mockImplementation(() => true);

  jest.doMock('http', () => ({
    createServer: jest.fn(() => httpServer),
  }), { virtual: true });
  jest.doMock('ws', () => ({ WebSocketServer }), { virtual: true });
  jest.doMock('../../../../api/auth', () => auth);
  jest.doMock('../../../../api/lib/db', () => ({
    initializeDatabase,
    runMigrations,
    closeDatabase,
  }));
  jest.doMock('../../../../api/lib/db/deviceRegistry', () => ({
    loadApiKeyHashes,
  }));
  jest.doMock('../../../../api/gdb/urlParser', () => ({
    parseGdbUrl,
  }));
  jest.doMock('../../../../api/gdb/sessionManager', () => ({
    createSessionManager: jest.fn(() => sm),
  }));

  const server = require('../../../../api/gdb/server');

  return {
    server,
    httpServer,
    WebSocketServer,
    auth,
    initializeDatabase,
    runMigrations,
    closeDatabase,
    loadApiKeyHashes,
    parseGdbUrl,
    processOn,
  };
}

describe('gdb server', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('verifyClient rejects requests with unrecognised paths', () => {
    const { server } = loadGdbServer();
    const verifyClient = server.wss.options.verifyClient;
    const done = jest.fn();

    verifyClient({ req: { url: '/not/gdb', headers: {} } }, done);
    expect(done).toHaveBeenCalledWith(false, 404, 'Not Found');
  });

  test('verifyClient rejects unauthenticated connections with 401 when keys exist', async () => {
    const { server, auth, parseGdbUrl } = loadGdbServer({
      agentKeys: [{ keyHash: 'a', username: 'alice' }],
    });
    await server.main();
    const verifyClient = server.wss.options.verifyClient;
    const done = jest.fn();

    parseGdbUrl.mockReturnValueOnce({ direction: 'in', hexkey: 'abc' });
    auth.matchBearer.mockReturnValueOnce(null);

    verifyClient({ req: { url: '/gdb/in/abc', headers: {} } }, done);
    expect(done).toHaveBeenCalledWith(false, 401, 'Unauthorized');
  });

  test('verifyClient accepts a connection whose token matches the scope', async () => {
    const { server, auth, parseGdbUrl } = loadGdbServer({
      agentKeys: [{ keyHash: 'a', username: 'alice' }],
    });
    await server.main();
    const verifyClient = server.wss.options.verifyClient;
    const done = jest.fn();

    parseGdbUrl.mockReturnValueOnce({ direction: 'in', hexkey: 'abc' });
    auth.matchBearer.mockReturnValueOnce('alice');

    verifyClient({ req: { url: '/gdb/in/abc', headers: { authorization: 'Bearer token' } } }, done);
    expect(done).toHaveBeenCalledWith(true);
  });

  test('verifyClient validates the in direction against agent keys and out against client keys', async () => {
    const agentKeys = [{ keyHash: 'agent-hash', username: 'alice' }];
    const clientKeys = [{ keyHash: 'client-hash', username: 'alice' }];
    const { server, auth, parseGdbUrl } = loadGdbServer({ agentKeys, clientKeys });
    await server.main();
    const verifyClient = server.wss.options.verifyClient;

    parseGdbUrl.mockReturnValueOnce({ direction: 'in', hexkey: 'abc' });
    auth.matchBearer.mockReturnValueOnce('alice');
    verifyClient({ req: { url: '/gdb/in/abc', headers: { authorization: 'Bearer agent' } } }, jest.fn());
    expect(auth.matchBearer).toHaveBeenLastCalledWith('Bearer agent', agentKeys);

    parseGdbUrl.mockReturnValueOnce({ direction: 'out', hexkey: 'abc' });
    auth.matchBearer.mockReturnValueOnce('alice');
    verifyClient({ req: { url: '/gdb/out/abc', headers: { authorization: 'Bearer client' } } }, jest.fn());
    expect(auth.matchBearer).toHaveBeenLastCalledWith('Bearer client', clientKeys);
  });

  test('verifyClient allows a direction with no configured keys (opt-in enforcement)', async () => {
    const { server, parseGdbUrl } = loadGdbServer({
      agentKeys: [{ keyHash: 'a', username: 'alice' }],
      clientKeys: [],
    });
    await server.main();
    const verifyClient = server.wss.options.verifyClient;
    const done = jest.fn();

    // No client keys configured -> the out direction is not gated.
    parseGdbUrl.mockReturnValueOnce({ direction: 'out', hexkey: 'abc' });
    verifyClient({ req: { url: '/gdb/out/abc', headers: {} } }, done);
    expect(done).toHaveBeenCalledWith(true);
  });

  test('main initializes the database and loads both key scopes before listening', async () => {
    const { server, initializeDatabase, runMigrations, loadApiKeyHashes, httpServer } = loadGdbServer();

    await server.main();

    expect(initializeDatabase).toHaveBeenCalledTimes(1);
    expect(runMigrations).toHaveBeenCalledTimes(1);
    expect(loadApiKeyHashes).toHaveBeenCalledWith('agent');
    expect(loadApiKeyHashes).toHaveBeenCalledWith('client');
    expect(httpServer.listen).toHaveBeenCalledTimes(1);
  });

  test('main exits when database initialization fails', async () => {
    const { server, httpServer } = loadGdbServer({
      db: {
        initializeDatabase: async () => {
          throw new Error('db offline');
        },
      },
    });

    await server.main();

    expect(process.stderr.write).toHaveBeenCalledWith('Failed to initialize database: db offline\n');
    expect(process.exit).toHaveBeenCalledWith(1);
    expect(httpServer.listen).not.toHaveBeenCalled();
  });
});
