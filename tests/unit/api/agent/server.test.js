'use strict';

const path = require('path');

function makeResponse({ statusCode = 200, headers = {}, body = '', location } = {}) {
  const handlers = {};
  return {
    statusCode,
    headers: location ? { ...headers, location } : headers,
    setEncoding: jest.fn(),
    on: jest.fn((event, handler) => {
      handlers[event] = handler;
      return this;
    }),
    emit(event, value) {
      if (handlers[event]) {
        handlers[event](value);
      }
    },
    pipe(dest) {
      setImmediate(() => {
        if (dest._handlers.finish) {
          dest._handlers.finish();
        }
      });
    },
    resume: jest.fn(),
  };
}

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
  const httpGet = jest.fn();
  const httpsGet = jest.fn();
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
    init: jest.fn(() => true),
  };
  const initializeDatabase = jest.fn().mockResolvedValue(undefined);
  const runMigrations = jest.fn().mockResolvedValue([]);
  const closeDatabase = jest.fn().mockResolvedValue(undefined);
  const persistUpload = jest.fn();
  const createApp = jest.fn(() => 'app-instance');
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
    repo: 'nstarke/embedded_linux_audit',
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
  if (options.auth) Object.assign(auth, options.auth);
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
    get: httpGet,
    createServer: jest.fn(() => httpServer),
  }), { virtual: true });
  jest.doMock('https', () => ({
    get: httpsGet,
    createServer: jest.fn(() => httpsServer),
  }), { virtual: true });
  jest.doMock('mime-types', () => ({
    lookup: jest.fn(() => 'application/octet-stream'),
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
  jest.doMock('../../../../api/agent/app', () => ({
    createApp,
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
    httpGet,
    httpsGet,
    httpServer,
    httpsServer,
    auth,
    initializeDatabase,
    runMigrations,
    closeDatabase,
    createApp,
    persistUpload,
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

  test('githubJsonGet fetches JSON and includes auth headers', async () => {
    const { server, httpsGet } = loadAgentServer();
    httpsGet.mockImplementation((url, options, cb) => {
      const res = makeResponse({ body: '{"ok":true}' });
      cb(res);
      res.emit('data', '{"ok":');
      res.emit('data', 'true}');
      res.emit('end');
      return { on: jest.fn() };
    });

    await expect(server.githubJsonGet('https://api.example.test/data', 'token-1')).resolves.toEqual({ ok: true });
    expect(httpsGet).toHaveBeenCalledWith('https://api.example.test/data', expect.objectContaining({
      headers: expect.objectContaining({
        Authorization: 'Bearer token-1',
        Accept: 'application/vnd.github+json',
      }),
    }), expect.any(Function));
  });

  test('getLatestRelease requests the GitHub latest release endpoint and rejects on HTTP error', async () => {
    const { server, httpsGet } = loadAgentServer();
    httpsGet
      .mockImplementationOnce((url, _options, cb) => {
        const res = makeResponse({ statusCode: 403 });
        cb(res);
        res.emit('end');
        return { on: jest.fn() };
      })
      .mockImplementationOnce((url, _options, cb) => {
        const res = makeResponse();
        cb(res);
        res.emit('data', '{"tag_name":"v1.2.3"}');
        res.emit('end');
        return { on: jest.fn() };
      });

    await expect(server.githubJsonGet('https://api.example.test/data')).rejects.toMatchObject({ message: 'HTTP 403', statusCode: 403 });
    await expect(server.getLatestRelease('owner/repo', 'tok')).resolves.toEqual({ tag_name: 'v1.2.3' });
    expect(httpsGet.mock.calls[1][0]).toBe('https://api.github.com/repos/owner/repo/releases/latest');
  });

  test('downloadFile follows redirects and cleans temporary files', async () => {
    const { server, fsMock, httpsGet } = loadAgentServer();
    httpsGet
      .mockImplementationOnce((_url, _options, cb) => {
        const res = makeResponse({ statusCode: 302, location: '/redirected.bin' });
        cb(res);
        return { on: jest.fn() };
      })
      .mockImplementationOnce((_url, _options, cb) => {
        const res = makeResponse({ statusCode: 200 });
        cb(res);
        return { on: jest.fn() };
      });

    await expect(server.downloadFile('https://example.test/file.bin', '/tmp/file.bin', 'tok')).resolves.toBeUndefined();
    expect(httpsGet).toHaveBeenCalledTimes(2);
    expect(fsMock.rm).toHaveBeenCalledWith('/tmp/file.bin', { force: true }, expect.any(Function));
  });

  test('releaseIdentity and cached release helpers handle expected values', async () => {
    const { server, fspMock } = loadAgentServer();
    fspMock.readFile.mockResolvedValueOnce('{"release":"v9.9.9"}');

    expect(server.releaseIdentity({ tag_name: 'v1.0.0' })).toBe('v1.0.0');
    expect(server.releaseIdentity({ id: 1234 })).toBe('1234');
    expect(server.releaseIdentity({})).toBe('');
    await expect(server.loadCachedReleaseIdentity('/tmp/assets')).resolves.toBe('v9.9.9');

    await server.saveCachedReleaseIdentity('/tmp/assets', 'v2.0.0');
    expect(fspMock.mkdir).toHaveBeenCalledWith('/tmp/assets', { recursive: true });
    expect(fspMock.writeFile).toHaveBeenCalledWith(
      path.join('/tmp/assets', '.release_state.json'),
      expect.stringContaining('"release": "v2.0.0"'),
      'utf8',
    );
  });

  test('clearDownloadedAssets preserves release state files and ignores missing directories', async () => {
    const { server, fspMock } = loadAgentServer();
    fspMock.readdir
      .mockResolvedValueOnce([
        { name: '.release_state.json', isFile: () => true, isSymbolicLink: () => false },
        { name: '.release_state.123', isFile: () => true, isSymbolicLink: () => false },
        { name: 'ela-x86_64', isFile: () => true, isSymbolicLink: () => false },
        { name: 'link.bin', isFile: () => false, isSymbolicLink: () => true },
      ])
      .mockRejectedValueOnce(Object.assign(new Error('missing'), { code: 'ENOENT' }));

    await server.clearDownloadedAssets('/tmp/assets');
    expect(fspMock.unlink).toHaveBeenCalledWith(path.join('/tmp/assets', 'ela-x86_64'));
    expect(fspMock.unlink).toHaveBeenCalledWith(path.join('/tmp/assets', 'link.bin'));
    expect(fspMock.unlink).not.toHaveBeenCalledWith(path.join('/tmp/assets', '.release_state.json'));
    await expect(server.clearDownloadedAssets('/tmp/missing')).resolves.toBeUndefined();
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

    loaded = loadAgentServer({ auth: { init: jest.fn(() => false) } });
    process.argv = ['node', 'server.js', '--validate-key'];
    await expect(loaded.server.main()).resolves.toBe(1);
    expect(loaded.consoleError).toHaveBeenCalledWith('error: --validate-key is set but ela.key is missing or contains no valid tokens');

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

  test('main honors CLI bootstrap flags for skip-asset-sync and starts an HTTP server', async () => {
    const loaded = loadAgentServer();
    process.argv = [
      'node', 'server.js',
      '--host', '127.0.0.1',
      '--port', '5050',
      '--data-dir', 'data-root',
      '--tests-dir', 'tests-root',
      '--log-prefix', 'logs/prefix',
      '--skip-asset-sync',
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
    expect(loaded.httpServer.listen).toHaveBeenCalledWith(5050, '127.0.0.1', expect.any(Function));
    expect(loaded.consoleLog).toHaveBeenCalledWith(expect.stringContaining('Skipping release asset sync; serving assets from'));
    expect(loaded.processOn).toHaveBeenCalledWith('SIGINT', expect.any(Function));
  });

  test('main creates an HTTPS server and syncs assets when requested', async () => {
    const loaded = loadAgentServer({
      fs: {
        existsSync: jest.fn(() => false),
      },
      fsp: {
        readFile: jest.fn().mockRejectedValue(new Error('missing')),
        access: jest.fn().mockRejectedValue(new Error('missing')),
        readdir: jest.fn().mockResolvedValue([]),
      },
    });
    loaded.httpsGet
      .mockImplementationOnce((_url, _options, cb) => {
        const res = makeResponse();
        cb(res);
        res.emit('data', '{"tag_name":"v1.2.3","assets":[{"name":"ela-x86_64","browser_download_url":"https://download.test/ela-x86_64"}]}');
        res.emit('end');
        return { on: jest.fn() };
      })
      .mockImplementationOnce((_url, _options, cb) => {
        const res = makeResponse({ statusCode: 200 });
        cb(res);
        return { on: jest.fn() };
      });

    process.argv = ['node', 'server.js', '--https', '--cert', 'certs/server.crt', '--key', 'certs/server.key'];
    await expect(loaded.server.main()).resolves.toBe(0);

    expect(loaded.execFileSync).toHaveBeenCalled();
    expect(loaded.httpsServer.listen).toHaveBeenCalledWith(5000, '0.0.0.0', expect.any(Function));
    expect(loaded.fspMock.writeFile).toHaveBeenCalledWith(
      path.join('/repo/api/agent/data/release_binaries', '.release_state.json'),
      expect.stringContaining('"release": "v1.2.3"'),
      'utf8',
    );
    expect(loaded.consoleLog).toHaveBeenCalledWith(expect.stringContaining('Downloaded 1 release asset(s)'));
  });

  // githubJsonGet – additional branches
  test('githubJsonGet omits Authorization header when no token is provided', async () => {
    const { server, httpsGet } = loadAgentServer();
    httpsGet.mockImplementation((_url, options, cb) => {
      const res = makeResponse();
      cb(res);
      res.emit('data', '{}');
      res.emit('end');
      return { on: jest.fn() };
    });

    await server.githubJsonGet('https://api.example.test/data');
    expect(httpsGet.mock.calls[0][1].headers).not.toHaveProperty('Authorization');
  });

  test('githubJsonGet rejects when the response body is not valid JSON', async () => {
    const { server, httpsGet } = loadAgentServer();
    httpsGet.mockImplementation((_url, _options, cb) => {
      const res = makeResponse();
      cb(res);
      res.emit('data', 'not-json');
      res.emit('end');
      return { on: jest.fn() };
    });

    await expect(server.githubJsonGet('https://api.example.test/data')).rejects.toThrow(SyntaxError);
  });

  // requestUrl
  test('requestUrl resolves with the response and selects the correct client', async () => {
    const { server, httpGet, httpsGet } = loadAgentServer();

    httpGet.mockImplementation((_url, _opts, cb) => {
      cb(makeResponse());
      return { on: jest.fn() };
    });
    const httpRes = await server.requestUrl('http://example.test/path', {});
    expect(httpGet).toHaveBeenCalledWith('http://example.test/path', expect.any(Object), expect.any(Function));
    expect(httpRes).toBeDefined();

    httpsGet.mockImplementation((_url, _opts, cb) => {
      cb(makeResponse());
      return { on: jest.fn() };
    });
    const httpsRes = await server.requestUrl('https://example.test/path', {});
    expect(httpsGet).toHaveBeenCalledWith('https://example.test/path', expect.any(Object), expect.any(Function));
    expect(httpsRes).toBeDefined();
  });

  test('requestUrl rejects on a network error', async () => {
    const { server, httpGet } = loadAgentServer();
    let errorHandler;
    httpGet.mockImplementation(() => ({
      on: jest.fn((event, handler) => {
        if (event === 'error') errorHandler = handler;
      }),
    }));

    const promise = server.requestUrl('http://example.test/path', {});
    errorHandler(new Error('network failure'));
    await expect(promise).rejects.toThrow('network failure');
  });

  // downloadFile – additional branches
  test('downloadFile rejects immediately when redirect count exceeds the limit', async () => {
    const { server } = loadAgentServer();
    await expect(server.downloadFile('https://example.test/file', '/tmp/f', null, 6)).rejects.toThrow('Too many redirects');
  });

  test('downloadFile rejects on a 4xx HTTP response', async () => {
    const { server, httpsGet } = loadAgentServer();
    httpsGet.mockImplementation((_url, _opts, cb) => {
      const res = makeResponse({ statusCode: 404 });
      cb(res);
      return { on: jest.fn() };
    });

    await expect(server.downloadFile('https://example.test/file', '/tmp/f', null)).rejects.toThrow('HTTP 404');
  });

  test('downloadFile rejects on a network-level error', async () => {
    const { server, httpsGet } = loadAgentServer();
    let errorHandler;
    httpsGet.mockImplementation((_url, _opts, _cb) => ({
      on: jest.fn((event, handler) => {
        if (event === 'error') errorHandler = handler;
      }),
    }));

    const promise = server.downloadFile('https://example.test/file', '/tmp/f', null);
    errorHandler(new Error('socket hang up'));
    await expect(promise).rejects.toThrow('socket hang up');
  });

  // clearDownloadedAssets – additional branches
  test('clearDownloadedAssets rethrows non-ENOENT errors', async () => {
    const { server, fspMock } = loadAgentServer();
    fspMock.readdir.mockRejectedValueOnce(Object.assign(new Error('permission denied'), { code: 'EACCES' }));
    await expect(server.clearDownloadedAssets('/tmp/assets')).rejects.toThrow('permission denied');
  });

  test('clearDownloadedAssets does not unlink directory entries', async () => {
    const { server, fspMock } = loadAgentServer();
    fspMock.readdir.mockResolvedValueOnce([
      { name: 'subdir', isFile: () => false, isSymbolicLink: () => false },
    ]);
    await server.clearDownloadedAssets('/tmp/assets');
    expect(fspMock.unlink).not.toHaveBeenCalled();
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

  // loadCachedReleaseIdentity – failure modes
  test('loadCachedReleaseIdentity returns null for missing file, invalid JSON, and non-string release', async () => {
    const { server, fspMock } = loadAgentServer();
    fspMock.readFile
      .mockRejectedValueOnce(new Error('ENOENT'))
      .mockResolvedValueOnce('not-valid-json')
      .mockResolvedValueOnce('{"release":42}')
      .mockResolvedValueOnce('{"release":""}');

    await expect(server.loadCachedReleaseIdentity('/dir')).resolves.toBeNull();
    await expect(server.loadCachedReleaseIdentity('/dir')).resolves.toBeNull();
    await expect(server.loadCachedReleaseIdentity('/dir')).resolves.toBeNull();
    await expect(server.loadCachedReleaseIdentity('/dir')).resolves.toBeNull();
  });

  // downloadReleaseAssets
  test('downloadReleaseAssets skips assets without a name or URL, and skips existing files', async () => {
    const { server, fspMock, httpsGet } = loadAgentServer();
    fspMock.access
      .mockResolvedValueOnce(undefined)       // existing.bin → exists, skip
      .mockRejectedValueOnce(new Error('not found')); // new.bin → not found, download

    httpsGet.mockImplementation((_url, _opts, cb) => {
      const res = makeResponse({ statusCode: 200 });
      cb(res);
      return { on: jest.fn() };
    });

    const release = {
      assets: [
        { name: null, browser_download_url: 'https://example.test/bad' },
        { name: 'existing.bin', browser_download_url: 'https://example.test/existing.bin' },
        { name: 'new.bin', browser_download_url: 'https://example.test/new.bin' },
      ],
    };

    const result = await server.downloadReleaseAssets(release, '/tmp/assets', null, false);
    expect(result.skippedExisting).toHaveLength(1);
    expect(result.downloaded).toHaveLength(1);
    expect(result.skippedExisting[0]).toContain('existing.bin');
    expect(result.downloaded[0]).toContain('new.bin');
  });

  // parseArgs
  test('parseArgs applies all recognised flags', () => {
    const { server } = loadAgentServer();
    const args = server.parseArgs([
      '--host', '127.0.0.1',
      '--port', '8080',
      '--log-prefix', 'logs/p',
      '--data-dir', 'data',
      '--repo', 'org/repo',
      '--assets-dir', 'assets',
      '--tests-dir', 'tests',
      '--github-token', 'tok',
      '--force-download',
      '--clean',
      '--https',
      '--verbose',
      '--cert', 'cert.pem',
      '--key', 'key.pem',
      '--validate-key',
      '--skip-asset-sync',
      '--reuse-last-data-dir',
    ]);
    expect(args).toMatchObject({
      host: '127.0.0.1',
      port: 8080,
      logPrefix: 'logs/p',
      dataDir: 'data',
      repo: 'org/repo',
      assetsDir: 'assets',
      testsDir: 'tests',
      githubToken: 'tok',
      forceDownload: true,
      clean: true,
      https: true,
      verbose: true,
      cert: 'cert.pem',
      key: 'key.pem',
      validateKey: true,
      skipAssetSync: true,
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
  test('main returns 1 when the GitHub API request fails', async () => {
    const loaded = loadAgentServer();
    loaded.httpsGet.mockImplementation((_url, _opts, cb) => {
      const res = makeResponse({ statusCode: 503 });
      cb(res);
      res.emit('end');
      return { on: jest.fn() };
    });

    process.argv = ['node', 'server.js'];
    await expect(loaded.server.main()).resolves.toBe(1);
    expect(loaded.consoleError).toHaveBeenCalledWith(expect.stringContaining('Failed to fetch/download release assets'));
  });

  test('main logs "No new release" when the cached release matches the latest', async () => {
    const loaded = loadAgentServer({
      fsp: {
        readFile: jest.fn().mockResolvedValue('{"release":"v1.0.0"}'),
        access: jest.fn().mockResolvedValue(undefined),
        readdir: jest.fn().mockResolvedValue([]),
      },
    });
    loaded.httpsGet.mockImplementationOnce((_url, _options, cb) => {
      const res = makeResponse();
      cb(res);
      res.emit('data', '{"tag_name":"v1.0.0","assets":[]}');
      res.emit('end');
      return { on: jest.fn() };
    });

    process.argv = ['node', 'server.js'];
    await expect(loaded.server.main()).resolves.toBe(0);
    expect(loaded.consoleLog).toHaveBeenCalledWith(expect.stringContaining('No new release'));
  });

  test('main clears and re-downloads assets when --force-download is set', async () => {
    const loaded = loadAgentServer({
      fsp: {
        readFile: jest.fn().mockRejectedValue(new Error('missing')),
        access: jest.fn().mockResolvedValue(undefined),
        readdir: jest.fn().mockResolvedValue([
          { name: 'old-binary', isFile: () => true, isSymbolicLink: () => false },
        ]),
      },
    });
    loaded.httpsGet.mockImplementationOnce((_url, _options, cb) => {
      const res = makeResponse();
      cb(res);
      res.emit('data', '{"tag_name":"v2.0.0","assets":[]}');
      res.emit('end');
      return { on: jest.fn() };
    });

    process.argv = ['node', 'server.js', '--force-download'];
    await expect(loaded.server.main()).resolves.toBe(0);
    expect(loaded.fspMock.unlink).toHaveBeenCalledWith(expect.stringContaining('old-binary'));
    expect(loaded.consoleLog).toHaveBeenCalledWith(expect.stringContaining('Force download enabled'));
  });

  test('main removes stale data directories when --clean is set', async () => {
    const loaded = loadAgentServer({
      fsp: {
        readdir: jest.fn().mockResolvedValue([
          { name: 'old-timestamp' },
        ]),
      },
    });

    process.argv = ['node', 'server.js', '--clean', '--skip-asset-sync'];
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
    process.argv = ['node', 'server.js', '--skip-asset-sync', '--reuse-last-data-dir'];
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
    process.argv = ['node', 'server.js', '--skip-asset-sync', '--reuse-last-data-dir'];
    await loaded2.server.main();
    expect(loaded2.consoleLog).toHaveBeenCalledWith(expect.stringContaining('Created'));
  });

  test('SIGINT handler closes the server and database then exits', async () => {
    const loaded = loadAgentServer();
    process.argv = ['node', 'server.js', '--skip-asset-sync'];
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
