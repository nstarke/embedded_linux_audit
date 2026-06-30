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
    send(value) {
      this.body = value;
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

describe('isa route', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  function register(listBinaryEntriesImpl, deps = {}) {
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
    return app.get.mock.calls[0][1];
  }

  test('registers the token-in-path route', () => {
    const { registerIsaRoute } = loadRegisterIsaRoute(async () => []);
    const app = { get: jest.fn() };
    registerIsaRoute(app, { assetsDir: '/assets', path, crypto, fsp: {}, isWithinRoot: () => true, mime: { lookup: () => '' }, verboseRequestLog: jest.fn(), verboseResponseLog: jest.fn() });
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
    const handler = app.get.mock.calls[0][1];
    const res = createRes();

    await handler({ params: { token: 'my-secret-token', isa: 'x86_64' } }, res);

    const expectedDir = path.join('/assets', 'users', sha256('my-secret-token'));
    expect(listBinaryEntries).toHaveBeenCalledWith(expectedDir, expect.anything(), '.release_state.json');
    expect(res.headers['content-type']).toBe('application/x-agent');
    // Sent as a path relative to the validated baseDir, scoped by `root`.
    expect(res.sentFile).toBe('ela-x86_64');
    expect(res.sentFileOptions).toEqual({ root: expectedDir });
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
    const handler = app.get.mock.calls[0][1];

    await handler({ params: { token: 'aaa', isa: 'x86_64' } }, createRes());
    await handler({ params: { token: 'bbb', isa: 'x86_64' } }, createRes());

    expect(listBinaryEntries).toHaveBeenNthCalledWith(1, path.join('/assets', 'users', sha256('aaa')), expect.anything(), '.release_state.json');
    expect(listBinaryEntries).toHaveBeenNthCalledWith(2, path.join('/assets', 'users', sha256('bbb')), expect.anything(), '.release_state.json');
  });
});
