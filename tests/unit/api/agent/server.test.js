'use strict';

const path = require('path');

function makeWriteStream() {
  const stream = {
    _handlers: {},
    on: jest.fn((event, handler) => {
      stream._handlers[event] = handler;
      return stream;
    }),
    close: jest.fn((cb) => {
      if (cb) cb();
    }),
  };
  return stream;
}

function loadAgentServer(options = {}) {
  jest.resetModules();

  const fsMock = {
    constants: { F_OK: 0 },
    createWriteStream: jest.fn(() => makeWriteStream()),
    rm: jest.fn((_path, _opts, cb) => cb && cb()),
    existsSync: jest.fn(() => false),
    mkdirSync: jest.fn(),
    readFileSync: jest.fn(() => 'file-bytes'),
  };
  const fspMock = {
    readFile: jest.fn(),
    writeFile: jest.fn().mockResolvedValue(undefined),
    mkdir: jest.fn().mockResolvedValue(undefined),
    readdir: jest.fn(),
    unlink: jest.fn().mockResolvedValue(undefined),
    rm: jest.fn().mockResolvedValue(undefined),
    access: jest.fn().mockResolvedValue(undefined),
  };
  const httpServer = {
    once: jest.fn(),
    listen: jest.fn((port, host, cb) => cb()),
    close: jest.fn((cb) => cb && cb()),
  };
  const httpsServer = {
    once: jest.fn(),
    listen: jest.fn((port, host, cb) => cb()),
    close: jest.fn((cb) => cb && cb()),
  };
  const auth = {
    init: jest.fn().mockResolvedValue(true),
  };
  const loadApiKeyHashes = jest.fn().mockResolvedValue([]);
  const initializeDatabase = jest.fn().mockResolvedValue(undefined);
  const runMigrations = jest.fn().mockResolvedValue([]);
  const closeDatabase = jest.fn().mockResolvedValue(undefined);
  const persistUpload = jest.fn();
  const createApp = jest.fn(() => 'app-instance');
  const createPcapWebSocketServer = jest.fn();
  const createWlanFuzzWebSocketServer = jest.fn();
  const selectStartupDataDir = jest.fn().mockResolvedValue({
    dataDir: '/repo/data/123',
    timestamp: '123',
    reusedExisting: false,
  });
  const resolveProjectPath = jest.fn((root, target) => path.isAbsolute(target) ? target : path.join(root, target));
  const getAgentServiceConfig = jest.fn(() => ({
    host: '0.0.0.0',
    port: 5000,
    logPrefix: 'post_requests',
    dataDir: 'api/agent/data',
    assetsDir: null,
    testsDir: 'tests',
  }));
  const execFileSync = jest.fn();
  const processOn = jest.spyOn(process, 'on').mockImplementation(() => process);
  const consoleLog = jest.spyOn(console, 'log').mockImplementation(() => {});
  const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
  const exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => undefined);

  if (options.fs) Object.assign(fsMock, options.fs);
  if (options.fsp) Object.assign(fspMock, options.fsp);
  if (options.auth) {
    if (options.auth.init) auth.init = options.auth.init;
  }
  if (options.db) {
    if (options.db.initializeDatabase) initializeDatabase.mockImplementation(options.db.initializeDatabase);
    if (options.db.runMigrations) runMigrations.mockImplementation(options.db.runMigrations);
    if (options.db.closeDatabase) closeDatabase.mockImplementation(options.db.closeDatabase);
  }
  if (options.serverUtils) {
    if (options.serverUtils.selectStartupDataDir) selectStartupDataDir.mockImplementation(options.serverUtils.selectStartupDataDir);
    if (options.serverUtils.resolveProjectPath) resolveProjectPath.mockImplementation(options.serverUtils.resolveProjectPath);
  }

  jest.doMock('fs', () => fsMock);
  jest.doMock('fs/promises', () => fspMock);
  jest.doMock('http', () => ({
    createServer: jest.fn(() => httpServer),
  }), { virtual: true });
  jest.doMock('https', () => ({
    createServer: jest.fn(() => httpsServer),
  }), { virtual: true });
  jest.doMock('child_process', () => ({
    execFileSync,
  }));
  jest.doMock('../../../../api/auth', () => auth);
  jest.doMock('../../../../api/lib/config', () => ({
    getAgentServiceConfig,
  }));
  jest.doMock('../../../../api/lib/db', () => ({
    initializeDatabase,
    runMigrations,
    closeDatabase,
  }));
  jest.doMock('../../../../api/lib/db/persistUpload', () => ({
    persistUpload,
  }));
  jest.doMock('../../../../api/lib/db/deviceRegistry', () => ({
    loadApiKeyHashes,
  }));
  jest.doMock('../../../../api/agent/app', () => ({
    createApp,
  }));
  jest.doMock('../../../../api/agent/pcapWebSocket', () => ({
    createPcapWebSocketServer,
  }));
  jest.doMock('../../../../api/agent/wlanFuzzWebSocket', () => ({
    createWlanFuzzWebSocketServer,
  }));
  jest.doMock('../../../../api/agent/serverUtils', () => ({
    findProjectRoot: jest.fn(() => '/repo'),
    isValidMacAddress: jest.fn(),
    normalizeContentType: jest.fn(),
    logPathForContentType: jest.fn(),
    augmentJsonPayload: jest.fn(),
    resolveProjectPath,
    selectStartupDataDir,
    isWithinRoot: jest.fn(),
    getClientIp: jest.fn(),
    sanitizeUploadPath: jest.fn(),
    writeUploadFile: jest.fn(),
  }));

  const server = require('../../../../api/agent/server');

  return {
    server,
    fsMock,
    fspMock,
    httpServer,
    httpsServer,
    auth,
    initializeDatabase,
    runMigrations,
    closeDatabase,
    createApp,
    createPcapWebSocketServer,
    persistUpload,
    loadApiKeyHashes,
    selectStartupDataDir,
    resolveProjectPath,
    getAgentServiceConfig,
    execFileSync,
    processOn,
    consoleLog,
    consoleError,
    exitSpy,
  };
}

describe('agent server', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
    process.argv = ['node', 'server.js'];
  });

  test('ensureSelfSignedCert skips existing files and otherwise creates certs with openssl', () => {
    const { server, fsMock, execFileSync } = loadAgentServer();
    fsMock.existsSync.mockReturnValueOnce(true).mockReturnValueOnce(true);

    server.ensureSelfSignedCert('/tmp/cert.pem', '/tmp/key.pem');
    expect(execFileSync).not.toHaveBeenCalled();

    fsMock.existsSync.mockReturnValue(false);
    server.ensureSelfSignedCert('/tmp/cert.pem', '/tmp/key.pem');
    expect(fsMock.mkdirSync).toHaveBeenCalledWith('/tmp', { recursive: true });
    expect(execFileSync).toHaveBeenCalledWith('openssl', expect.arrayContaining([
      'req',
      '-x509',
      '-keyout',
      '/tmp/key.pem',
      '-out',
      '/tmp/cert.pem',
    ]), { stdio: 'ignore' });
  });

  test('main returns 1 on invalid CLI arguments and auth/database failures', async () => {
    let loaded = loadAgentServer();
    process.argv = ['node', 'server.js', '--bad-flag'];
    await expect(loaded.server.main()).resolves.toBe(1);
    expect(loaded.consoleError).toHaveBeenCalledWith('Unknown argument: --bad-flag');

    loaded = loadAgentServer({ auth: { init: jest.fn().mockResolvedValue(false) } });
    process.argv = ['node', 'server.js'];
    await expect(loaded.server.main()).resolves.toBe(1);
    expect(loaded.consoleError).toHaveBeenCalledWith('error: no API keys are configured in the database');

    loaded = loadAgentServer({
      db: {
        initializeDatabase: async () => {
          throw new Error('db unavailable');
        },
      },
    });
    process.argv = ['node', 'server.js'];
    await expect(loaded.server.main()).resolves.toBe(1);
    expect(loaded.consoleError).toHaveBeenCalledWith('Failed to initialize database: db unavailable');
  });

  test('main starts an HTTP server and serves per-user binaries', async () => {
    const loaded = loadAgentServer();
    process.argv = [
      'node', 'server.js',
      '--host', '127.0.0.1',
      '--port', '5050',
      '--data-dir', 'data-root',
      '--tests-dir', 'tests-root',
      '--log-prefix', 'logs/prefix',
      '--reuse-last-data-dir',
      '--verbose',
    ];

    await expect(loaded.server.main()).resolves.toBe(0);

    expect(loaded.initializeDatabase).toHaveBeenCalled();
    expect(loaded.runMigrations).toHaveBeenCalled();
    expect(loaded.selectStartupDataDir).toHaveBeenCalledWith('/repo/data-root', {
      reuseLastTimestampDir: true,
    });
    expect(loaded.createApp).toHaveBeenCalledWith(expect.objectContaining({
      logPrefix: '/repo/logs/prefix',
      dataDir: '/repo/data/123',
      testsDir: '/repo/tests-root',
      assetsDir: path.join('/repo/data-root', 'release_binaries'),
      verbose: true,
      persistUpload: loaded.persistUpload,
    }));
    // The per-user binary directory is created under the shared assets dir.
    expect(loaded.fspMock.mkdir).toHaveBeenCalledWith(
      path.join('/repo/data-root', 'release_binaries', 'users'),
      { recursive: true },
    );
    expect(loaded.createPcapWebSocketServer).toHaveBeenCalledWith({
      server: loaded.httpServer,
      dataDir: '/repo/data/123',
      persistUpload: loaded.persistUpload,
      verbose: true,
    });
    expect(loaded.httpServer.listen).toHaveBeenCalledWith(5050, '127.0.0.1', expect.any(Function));
    expect(loaded.consoleLog).toHaveBeenCalledWith(expect.stringContaining('Serving per-user agent binaries'));
    expect(loaded.processOn).toHaveBeenCalledWith('SIGINT', expect.any(Function));
  });

  test('main creates an HTTPS server with a generated self-signed cert', async () => {
    const loaded = loadAgentServer({
      fs: {
        existsSync: jest.fn(() => false),
      },
    });

    process.argv = ['node', 'server.js', '--https', '--cert', 'certs/server.crt', '--key', 'certs/server.key'];
    await expect(loaded.server.main()).resolves.toBe(0);

    expect(loaded.execFileSync).toHaveBeenCalled();
    expect(loaded.httpsServer.listen).toHaveBeenCalledWith(5000, '0.0.0.0', expect.any(Function));
  });

  // removeDirectoryContents
  test('removeDirectoryContents removes entries not in preservedNames', async () => {
    const { server, fspMock } = loadAgentServer();
    fspMock.readdir.mockResolvedValueOnce([
      { name: 'keep' },
      { name: 'delete-me' },
    ]);

    await server.removeDirectoryContents('/tmp/dir', new Set(['keep']));
    expect(fspMock.rm).toHaveBeenCalledWith('/tmp/dir/delete-me', { recursive: true, force: true });
    expect(fspMock.rm).not.toHaveBeenCalledWith('/tmp/dir/keep', expect.any(Object));
  });

  test('removeDirectoryContents swallows ENOENT', async () => {
    const { server, fspMock } = loadAgentServer();
    fspMock.readdir.mockRejectedValueOnce(Object.assign(new Error('no dir'), { code: 'ENOENT' }));
    await expect(server.removeDirectoryContents('/tmp/missing')).resolves.toBeUndefined();
  });

  test('removeDirectoryContents rethrows non-ENOENT errors', async () => {
    const { server, fspMock } = loadAgentServer();
    fspMock.readdir.mockRejectedValueOnce(Object.assign(new Error('perm denied'), { code: 'EACCES' }));
    await expect(server.removeDirectoryContents('/tmp/dir')).rejects.toThrow('perm denied');
  });

  // parseArgs
  test('parseArgs applies all recognised flags', () => {
    const { server } = loadAgentServer();
    const args = server.parseArgs([
      '--host', '127.0.0.1',
      '--port', '8080',
      '--log-prefix', 'logs/p',
      '--data-dir', 'data',
      '--assets-dir', 'assets',
      '--tests-dir', 'tests',
      '--clean',
      '--https',
      '--verbose',
      '--cert', 'cert.pem',
      '--key', 'key.pem',
      '--reuse-last-data-dir',
    ]);
    expect(args).toMatchObject({
      host: '127.0.0.1',
      port: 8080,
      logPrefix: 'logs/p',
      dataDir: 'data',
      assetsDir: 'assets',
      testsDir: 'tests',
      clean: true,
      https: true,
      verbose: true,
      cert: 'cert.pem',
      key: 'key.pem',
      reuseLastDataDir: true,
    });
  });

  test('parseArgs throws on an invalid port value', () => {
    const { server } = loadAgentServer();
    expect(() => server.parseArgs(['--port', '99999'])).toThrow(/Invalid --port/);
    expect(() => server.parseArgs(['--port', 'abc'])).toThrow(/Invalid --port/);
  });

  test('parseArgs --help calls process.exit(0)', () => {
    const { server, exitSpy } = loadAgentServer();
    server.parseArgs(['--help']);
    expect(exitSpy).toHaveBeenCalledWith(0);
  });

  // main – additional paths
  test('main removes stale data directories when --clean is set', async () => {
    const loaded = loadAgentServer({
      fsp: {
        readdir: jest.fn().mockResolvedValue([
          { name: 'old-timestamp' },
        ]),
      },
    });

    process.argv = ['node', 'server.js', '--clean'];
    await expect(loaded.server.main()).resolves.toBe(0);
    expect(loaded.fspMock.rm).toHaveBeenCalledWith(
      expect.stringContaining('old-timestamp'),
      { recursive: true, force: true },
    );
  });

  test('main logs "Reusing" or "Created" based on whether an existing data dir was found', async () => {
    const loaded = loadAgentServer({
      serverUtils: {
        selectStartupDataDir: jest.fn().mockResolvedValue({
          dataDir: '/repo/data/999',
          timestamp: '999',
          reusedExisting: true,
        }),
      },
    });
    process.argv = ['node', 'server.js', '--reuse-last-data-dir'];
    await loaded.server.main();
    expect(loaded.consoleLog).toHaveBeenCalledWith(expect.stringContaining('Reusing'));

    const loaded2 = loadAgentServer({
      serverUtils: {
        selectStartupDataDir: jest.fn().mockResolvedValue({
          dataDir: '/repo/data/1000',
          timestamp: '1000',
          reusedExisting: false,
        }),
      },
    });
    process.argv = ['node', 'server.js', '--reuse-last-data-dir'];
    await loaded2.server.main();
    expect(loaded2.consoleLog).toHaveBeenCalledWith(expect.stringContaining('Created'));
  });

  test('SIGINT handler closes the server and database then exits', async () => {
    const loaded = loadAgentServer();
    process.argv = ['node', 'server.js'];
    await loaded.server.main();

    const sigintCall = loaded.processOn.mock.calls.find(([event]) => event === 'SIGINT');
    expect(sigintCall).toBeDefined();

    sigintCall[1]();
    // flush microtasks so the async close callback completes
    await new Promise((resolve) => setImmediate(resolve));

    expect(loaded.httpServer.close).toHaveBeenCalled();
    expect(loaded.closeDatabase).toHaveBeenCalled();
    expect(loaded.exitSpy).toHaveBeenCalledWith(0);
  });
});
