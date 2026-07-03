'use strict';

const registerModuleDownloadRoute = require('../../../../api/agent/routes/moduleDownload');

function createApp() {
  const gets = {};
  return {
    gets,
    get(routePath, handler) { gets[routePath] = handler; },
  };
}

function createRes() {
  return {
    statusCode: 200,
    headers: {},
    body: undefined,
    sentFile: undefined,
    headersSent: false,
    status(code) { this.statusCode = code; return this; },
    type(value) { this.headers['content-type'] = value; return this; },
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    send(value) { this.body = value; return this; },
    // Emulate a successful Express sendFile: the file streams and the callback
    // fires with no error. Tests that need a send failure override this.
    sendFile(filePath, cb) {
      this.sentFile = filePath;
      this.headersSent = true;
      if (cb) cb();
      return this;
    },
  };
}

function register(overrides = {}) {
  const app = createApp();
  const deps = {
    path: require('path'),
    fsp: {
      stat: jest.fn().mockResolvedValue({ isFile: () => true, size: 13 }),
    },
    consumeDownloadToken: jest.fn().mockResolvedValue({
      id: 7,
      artifactPath: '/data/agent/aa:bb:cc:dd:ee:ff/modules/7/ela_kmod.ko',
    }),
    verboseRequestLog: jest.fn(),
    verboseResponseLog: jest.fn(),
    ...overrides,
  };
  registerModuleDownloadRoute(app, deps);
  return { app, deps };
}

describe('module download route', () => {
  test('serves the artifact for a valid token', async () => {
    const { app, deps } = register();
    const res = createRes();

    await app.gets['/module/:token']({ params: { token: 'tok123' } }, res);

    expect(deps.consumeDownloadToken).toHaveBeenCalledWith('tok123');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('application/octet-stream');
    expect(res.headers['content-disposition']).toContain('ela_kmod.ko');
    expect(res.sentFile).toBe('/data/agent/aa:bb:cc:dd:ee:ff/modules/7/ela_kmod.ko');
    expect(deps.fsp.stat).toHaveBeenCalledWith('/data/agent/aa:bb:cc:dd:ee:ff/modules/7/ela_kmod.ko');
    expect(deps.verboseResponseLog).toHaveBeenCalledWith(expect.anything(), 200, 13);
  });

  test('404s an unknown, expired, or used token uniformly', async () => {
    const { app } = register({
      consumeDownloadToken: jest.fn().mockResolvedValue(null),
    });
    const res = createRes();

    await app.gets['/module/:token']({ params: { token: 'nope' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });

  test('404s when the token resolver throws', async () => {
    const { app } = register({
      consumeDownloadToken: jest.fn().mockRejectedValue(new Error('db down')),
    });
    const res = createRes();

    await app.gets['/module/:token']({ params: { token: 'tok' } }, res);

    expect(res.statusCode).toBe(404);
  });

  test('404s when the artifact file is missing', async () => {
    const { app } = register({
      fsp: { stat: jest.fn().mockRejectedValue(Object.assign(new Error('missing'), { code: 'ENOENT' })) },
    });
    const res = createRes();

    await app.gets['/module/:token']({ params: { token: 'tok' } }, res);

    expect(res.statusCode).toBe(404);
  });

  test('404s when sendFile fails after stat succeeds', async () => {
    const { app } = register();
    const res = createRes();
    // Emulate a stream error surfaced through the sendFile callback before any
    // bytes reach the client.
    res.sendFile = function (filePath, cb) {
      this.sentFile = filePath;
      cb(Object.assign(new Error('stream broke'), { code: 'ENOENT' }));
      return this;
    };

    await app.gets['/module/:token']({ params: { token: 'tok' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });
});
