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

  test('?vermagic=device streams the vermagic-patched bytes, not the raw file', async () => {
    const patchVermagic = jest.fn(() => Buffer.from('PATCHED-KO-BYTES'));
    const { app, deps } = register({
      fsp: {
        stat: jest.fn().mockResolvedValue({ isFile: () => true, size: 13 }),
        readFile: jest.fn().mockResolvedValue(Buffer.from('RAW-KO')),
      },
      consumeDownloadToken: jest.fn().mockResolvedValue({
        id: 7,
        artifactPath: '/data/agent/aa:bb:cc:dd:ee:ff/modules/7/ela_kmod.ko',
        deviceVermagic: '3.12.19-rt30 SMP mod_unload ARMv7 p2v8 ',
      }),
      patchVermagic,
    });
    const res = createRes();

    await app.gets['/module/:token']({ params: { token: 'tok' }, query: { vermagic: 'device' } }, res);

    expect(deps.fsp.readFile).toHaveBeenCalledWith('/data/agent/aa:bb:cc:dd:ee:ff/modules/7/ela_kmod.ko');
    expect(patchVermagic).toHaveBeenCalledWith(Buffer.from('RAW-KO'), '3.12.19-rt30 SMP mod_unload ARMv7 p2v8 ');
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual(Buffer.from('PATCHED-KO-BYTES'));
    expect(res.headers['content-length']).toBe('PATCHED-KO-BYTES'.length);
    expect(res.sentFile).toBeUndefined(); // did NOT fall through to sendFile
    expect(deps.verboseResponseLog).toHaveBeenCalledWith(expect.anything(), 200, 'PATCHED-KO-BYTES'.length);
  });

  test('falls back to the unpatched file when patching throws', async () => {
    const { app } = register({
      fsp: {
        stat: jest.fn().mockResolvedValue({ isFile: () => true, size: 13 }),
        readFile: jest.fn().mockResolvedValue(Buffer.from('RAW-KO')),
      },
      consumeDownloadToken: jest.fn().mockResolvedValue({
        id: 7,
        artifactPath: '/data/agent/aa:bb:cc:dd:ee:ff/modules/7/ela_kmod.ko',
        deviceVermagic: 'x',
      }),
      patchVermagic: jest.fn(() => { throw new Error('no vermagic in .modinfo'); }),
    });
    const res = createRes();

    await app.gets['/module/:token']({ params: { token: 'tok' }, query: { vermagic: 'device' } }, res);

    expect(res.statusCode).toBe(200);
    expect(res.sentFile).toBe('/data/agent/aa:bb:cc:dd:ee:ff/modules/7/ela_kmod.ko');
  });

  test('does not patch without the ?vermagic=device flag', async () => {
    const patchVermagic = jest.fn();
    const { app } = register({
      consumeDownloadToken: jest.fn().mockResolvedValue({
        id: 7,
        artifactPath: '/data/agent/aa:bb:cc:dd:ee:ff/modules/7/ela_kmod.ko',
        deviceVermagic: 'x',
      }),
      patchVermagic,
    });
    const res = createRes();

    await app.gets['/module/:token']({ params: { token: 'tok' }, query: {} }, res);

    expect(patchVermagic).not.toHaveBeenCalled();
    expect(res.sentFile).toBe('/data/agent/aa:bb:cc:dd:ee:ff/modules/7/ela_kmod.ko');
  });
});
