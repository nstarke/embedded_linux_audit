'use strict';

const path = require('path');

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
    sendFile(value) {
      this.sentFile = value;
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
      fsp: {
        readdir: jest.fn(),
      },
      isWithinRoot: jest.fn(() => true),
      mime: {
        lookup: jest.fn(() => 'application/x-agent'),
      },
      verboseRequestLog: jest.fn(),
      verboseResponseLog: jest.fn(),
      ...deps,
    });
    return app.get.mock.calls[0][1];
  }

  test('rejects invalid ISA path segments', async () => {
    const handler = register(async () => []);
    const res = createRes();

    await handler({ params: { isa: '../bad' } }, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid path\n');
  });

  test('returns not found when no release binary matches the ISA', async () => {
    const handler = register(async () => [{ isa: 'x86_64', fileName: 'ela-x86_64' }]);
    const res = createRes();

    await handler({ params: { isa: 'arm64' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });

  test('returns not found when the matched asset resolves outside the assets directory', async () => {
    const handler = register(async () => [{ isa: 'x86_64', fileName: 'ela-x86_64' }], {
      isWithinRoot: jest.fn(() => false),
    });
    const res = createRes();

    await handler({ params: { isa: 'x86_64' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });

  test('serves the matched release binary with the looked-up mime type', async () => {
    const mime = { lookup: jest.fn(() => 'application/x-agent') };
    const handler = register(async () => [{ isa: 'x86_64', fileName: 'ela-x86_64' }], { mime });
    const res = createRes();

    await handler({ params: { isa: 'x86_64' } }, res);

    expect(mime.lookup).toHaveBeenCalledWith(path.resolve('/assets', 'ela-x86_64'));
    expect(res.headers['content-type']).toBe('application/x-agent');
    expect(res.sentFile).toBe(path.resolve('/assets', 'ela-x86_64'));
  });
});
