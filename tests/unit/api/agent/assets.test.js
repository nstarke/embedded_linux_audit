'use strict';

const path = require('path');
const registerAssetRoute = require('../../../../api/agent/routes/assets');

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

describe('assets route', () => {
  function register(deps = {}) {
    const app = { get: jest.fn() };
    registerAssetRoute(app, {
      assetsDir: '/assets',
      path,
      fsp: {
        stat: jest.fn(),
      },
      isWithinRoot: jest.fn(() => true),
      mime: {
        lookup: jest.fn(() => 'application/octet-stream'),
      },
      verboseRequestLog: jest.fn(),
      verboseResponseLog: jest.fn(),
      ...deps,
    });
    return app.get.mock.calls[0][1];
  }

  test('serves an existing asset with the resolved mime type', async () => {
    const mime = { lookup: jest.fn(() => 'application/x-elf') };
    const handler = register({
      fsp: {
        stat: jest.fn().mockResolvedValue({ isFile: () => true }),
      },
      mime,
    });
    const res = createRes();

    await handler({ params: { name: 'ela-x86_64' } }, res);

    expect(mime.lookup).toHaveBeenCalledWith(path.resolve('/assets', 'ela-x86_64'));
    expect(res.headers['content-type']).toBe('application/x-elf');
    expect(res.sentFile).toBe(path.resolve('/assets', 'ela-x86_64'));
  });

  test('returns not found when the asset resolves outside the assets directory', async () => {
    const handler = register({
      isWithinRoot: jest.fn(() => false),
    });
    const res = createRes();

    await handler({ params: { name: '../escape' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });

  test('returns not found when the asset is missing', async () => {
    const handler = register({
      fsp: {
        stat: jest.fn().mockRejectedValue(new Error('missing')),
      },
    });
    const res = createRes();

    await handler({ params: { name: 'missing.bin' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });
});
