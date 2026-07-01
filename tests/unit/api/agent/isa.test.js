'use strict';

const path = require('path');
const crypto = require('crypto');

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function createRes() {
  return {
    statusCode: 200,
    headers: {},
    body: '',
    sentFile: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    type(value) {
      this.headers['content-type'] = value;
      return this;
    },
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
      return this;
    },
    send(value) {
      this.body = value;
      return this;
    },
    json(value) {
      this.jsonBody = value;
      this.headers['content-type'] = 'application/json';
      return this;
    },
    sendFile(value, options) {
      this.sentFile = value;
      this.sentFileOptions = options;
      return this;
    },
  };
}

function loadRegisterIsaRoute(listBinaryEntriesImpl) {
  jest.resetModules();
  const listBinaryEntries = jest.fn(listBinaryEntriesImpl);

  jest.doMock('../../../../api/agent/routes/shared', () => ({
    ...jest.requireActual('../../../../api/agent/routes/shared'),
    listBinaryEntries,
  }));

  const registerIsaRoute = require('../../../../api/agent/routes/isa');
  return { registerIsaRoute, listBinaryEntries };
}

// Select a route handler by its registered path (order-independent).
function handlerFor(app, routePath) {
  const call = app.get.mock.calls.find(([p]) => p === routePath);
  return call && call[1];
}

describe('isa route', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  // Build the app and return handlers for both routes plus the raw app.
  function registerApp(listBinaryEntriesImpl, deps = {}) {
    const { registerIsaRoute } = loadRegisterIsaRoute(listBinaryEntriesImpl);
    const app = { get: jest.fn() };
    registerIsaRoute(app, {
      assetsDir: '/assets',
      releaseStateFile: '.release_state.json',
      path,
      crypto,
      fsp: { readdir: jest.fn() },
      isWithinRoot: jest.fn(() => true),
      mime: { lookup: jest.fn(() => 'application/x-agent') },
      verboseRequestLog: jest.fn(),
      verboseResponseLog: jest.fn(),
      ...deps,
    });
    return {
      app,
      download: handlerFor(app, '/isa/:token/:isa'),
      list: handlerFor(app, '/isa/:token'),
    };
  }

  // Back-compat: existing tests drive the download handler.
  function register(listBinaryEntriesImpl, deps = {}) {
    return registerApp(listBinaryEntriesImpl, deps).download;
  }

  test('registers both the list and download token-in-path routes', () => {
    const { registerIsaRoute } = loadRegisterIsaRoute(async () => []);
    const app = { get: jest.fn() };
    registerIsaRoute(app, { assetsDir: '/assets', path, crypto, fsp: {}, isWithinRoot: () => true, mime: { lookup: () => '' }, verboseRequestLog: jest.fn(), verboseResponseLog: jest.fn() });
    expect(app.get).toHaveBeenCalledWith('/isa/:token', expect.any(Function));
    expect(app.get).toHaveBeenCalledWith('/isa/:token/:isa', expect.any(Function));
  });

  test('rejects invalid ISA path segments', async () => {
    const handler = register(async () => []);
    const res = createRes();

    await handler({ params: { token: 'tok', isa: '../bad' } }, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid path\n');
  });

  test('returns not found when no binary matches the ISA', async () => {
    const handler = register(async () => [{ isa: 'x86_64', fileName: 'ela-x86_64' }]);
    const res = createRes();

    await handler({ params: { token: 'tok', isa: 'arm64' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });

  test('returns not found when the matched asset resolves outside the per-user directory', async () => {
    const handler = register(async () => [{ isa: 'x86_64', fileName: 'ela-x86_64' }], {
      isWithinRoot: jest.fn(() => false),
    });
    const res = createRes();

    await handler({ params: { token: 'tok', isa: 'x86_64' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });

  test('serves the binary from the directory keyed by sha256(token)', async () => {
    const mime = { lookup: jest.fn(() => 'application/x-agent') };
    const listBinaryEntries = jest.fn(async () => [{ isa: 'x86_64', fileName: 'ela-x86_64' }]);
    const { registerIsaRoute } = loadRegisterIsaRoute(listBinaryEntries);
    const app = { get: jest.fn() };
    registerIsaRoute(app, {
      assetsDir: '/assets',
      releaseStateFile: '.release_state.json',
      path,
      crypto,
      fsp: { readdir: jest.fn() },
      isWithinRoot: jest.fn(() => true),
      mime,
      verboseRequestLog: jest.fn(),
      verboseResponseLog: jest.fn(),
    });
    const handler = handlerFor(app, '/isa/:token/:isa');
    const res = createRes();

    await handler({ params: { token: 'my-secret-token', isa: 'x86_64' } }, res);

    const expectedDir = path.join('/assets', 'users', sha256('my-secret-token'));
    expect(listBinaryEntries).toHaveBeenCalledWith(expectedDir, expect.anything(), '.release_state.json');
    expect(res.headers['content-type']).toBe('application/x-agent');
    // Sent as a path relative to the validated baseDir, scoped by `root`.
    expect(res.sentFile).toBe('ela-x86_64');
    expect(res.sentFileOptions).toEqual({ root: expectedDir });
    expect(res.headers['content-disposition']).toBe('attachment; filename="ela-x86_64"');
  });

  test('a different token maps to a different directory', async () => {
    const listBinaryEntries = jest.fn(async () => [{ isa: 'x86_64', fileName: 'ela-x86_64' }]);
    const { registerIsaRoute } = loadRegisterIsaRoute(listBinaryEntries);
    const app = { get: jest.fn() };
    registerIsaRoute(app, {
      assetsDir: '/assets', releaseStateFile: '.release_state.json', path, crypto,
      fsp: { readdir: jest.fn() }, isWithinRoot: jest.fn(() => true),
      mime: { lookup: jest.fn(() => 'application/x-agent') },
      verboseRequestLog: jest.fn(), verboseResponseLog: jest.fn(),
    });
    const handler = handlerFor(app, '/isa/:token/:isa');

    await handler({ params: { token: 'aaa', isa: 'x86_64' } }, createRes());
    await handler({ params: { token: 'bbb', isa: 'x86_64' } }, createRes());

    expect(listBinaryEntries).toHaveBeenNthCalledWith(1, path.join('/assets', 'users', sha256('aaa')), expect.anything(), '.release_state.json');
    expect(listBinaryEntries).toHaveBeenNthCalledWith(2, path.join('/assets', 'users', sha256('bbb')), expect.anything(), '.release_state.json');
  });

  describe('GET /isa/:token (list)', () => {
    test('returns the available downloads for a valid token', async () => {
      const entries = [
        { isa: 'aarch64-le', fileName: 'ela-aarch64-le' },
        { isa: 'x86_64', fileName: 'ela-x86_64' },
      ];
      const { list, app } = registerApp(async () => entries);
      void app;
      const res = createRes();

      await list({ params: { token: 'my-secret-token' } }, res);

      expect(res.statusCode).toBe(200);
      expect(res.jsonBody).toEqual({
        isas: ['aarch64-le', 'x86_64'],
        downloads: [
          { isa: 'aarch64-le', path: '/isa/my-secret-token/aarch64-le' },
          { isa: 'x86_64', path: '/isa/my-secret-token/x86_64' },
        ],
      });
    });

    test('looks up the launcher set by sha256(token)', async () => {
      const listBinaryEntries = jest.fn(async () => [{ isa: 'x86_64', fileName: 'ela-x86_64' }]);
      const { list } = registerApp(listBinaryEntries);

      await list({ params: { token: 'tok' } }, createRes());

      expect(listBinaryEntries).toHaveBeenCalledWith(
        path.join('/assets', 'users', sha256('tok')),
        expect.anything(),
        '.release_state.json',
      );
    });

    test('returns 404 for an unknown/unprovisioned token (empty set)', async () => {
      const { list } = registerApp(async () => []);
      const res = createRes();

      await list({ params: { token: 'nope' } }, res);

      expect(res.statusCode).toBe(404);
      expect(res.body).toBe('not found\n');
    });

    test('url-encodes the token in the returned download paths', async () => {
      const { list } = registerApp(async () => [{ isa: 'x86_64', fileName: 'ela-x86_64' }]);
      const res = createRes();

      await list({ params: { token: 'a b/c' } }, res);

      expect(res.jsonBody.downloads[0].path).toBe('/isa/a%20b%2Fc/x86_64');
    });
  });
});
