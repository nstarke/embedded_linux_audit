'use strict';

const flush = () => new Promise((resolve) => setImmediate(resolve));

function loadGdbServer(options = {}) {
  jest.resetModules();

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
    resolveBearer: jest.fn().mockResolvedValue(true),
  };
  const initializeDatabase = jest.fn().mockResolvedValue(undefined);
  const runMigrations = jest.fn().mockResolvedValue([]);
  const closeDatabase = jest.fn().mockResolvedValue(undefined);
  const loadApiKeyHashes = jest.fn((scope) => Promise.resolve(scope === 'client' ? ['client'] : ['agent']));
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
    server, httpServer, WebSocketServer, auth,
    initializeDatabase, runMigrations, closeDatabase, loadApiKeyHashes, parseGdbUrl, processOn,
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

  test('verifyClient rejects with 401 when the scope rejects the token', async () => {
    const { server, auth, parseGdbUrl } = loadGdbServer();
    const verifyClient = server.wss.options.verifyClient;
    const done = jest.fn();

    parseGdbUrl.mockReturnValueOnce({ direction: 'in', hexkey: 'abc' });
    auth.resolveBearer.mockResolvedValueOnce(false);

    verifyClient({ req: { url: '/gdb/in/abc', headers: {} } }, done);
    await flush();
    expect(done).toHaveBeenCalledWith(false, 401, 'Unauthorized');
  });

  test('verifyClient accepts a connection the scope authorizes', async () => {
    const { server, auth, parseGdbUrl } = loadGdbServer();
    const verifyClient = server.wss.options.verifyClient;
    const done = jest.fn();

    parseGdbUrl.mockReturnValueOnce({ direction: 'in', hexkey: 'abc' });
    auth.resolveBearer.mockResolvedValueOnce('alice');

    verifyClient({ req: { url: '/gdb/in/abc', headers: { authorization: 'Bearer token' } } }, done);
    await flush();
    expect(done).toHaveBeenCalledWith(true);
  });

  test('verifyClient resolves the in direction against agent keys, out against client keys', async () => {
    const { server, auth, parseGdbUrl, loadApiKeyHashes } = loadGdbServer();
    const verifyClient = server.wss.options.verifyClient;

    parseGdbUrl.mockReturnValueOnce({ direction: 'in', hexkey: 'abc' });
    auth.resolveBearer.mockResolvedValueOnce('alice');
    verifyClient({ req: { url: '/gdb/in/abc', headers: { authorization: 'Bearer agent' } } }, jest.fn());
    await flush();
    expect(auth.resolveBearer.mock.calls[0][0]).toBe('Bearer agent');
    expect(auth.resolveBearer.mock.calls[0][2]).toBe(false);
    await auth.resolveBearer.mock.calls[0][1](); // the scope loader
    expect(loadApiKeyHashes).toHaveBeenLastCalledWith('agent');

    parseGdbUrl.mockReturnValueOnce({ direction: 'out', hexkey: 'abc' });
    auth.resolveBearer.mockResolvedValueOnce('alice');
    verifyClient({ req: { url: '/gdb/out/abc', headers: { authorization: 'Bearer client' } } }, jest.fn());
    await flush();
    await auth.resolveBearer.mock.calls[1][1]();
    expect(loadApiKeyHashes).toHaveBeenLastCalledWith('client');
  });

  test('verifyClient rejects with 401 when the key lookup errors', async () => {
    const { server, auth, parseGdbUrl } = loadGdbServer();
    const verifyClient = server.wss.options.verifyClient;
    const done = jest.fn();

    parseGdbUrl.mockReturnValueOnce({ direction: 'out', hexkey: 'abc' });
    auth.resolveBearer.mockRejectedValueOnce(new Error('db down'));

    verifyClient({ req: { url: '/gdb/out/abc', headers: {} } }, done);
    await flush();
    expect(done).toHaveBeenCalledWith(false, 401, 'Unauthorized');
  });

  test('main initializes the database before listening (no key preloading)', async () => {
    const { server, initializeDatabase, runMigrations, loadApiKeyHashes, httpServer } = loadGdbServer();

    await server.main();

    expect(initializeDatabase).toHaveBeenCalledTimes(1);
    expect(runMigrations).toHaveBeenCalledTimes(1);
    expect(loadApiKeyHashes).not.toHaveBeenCalled(); // keys are read per connection
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
