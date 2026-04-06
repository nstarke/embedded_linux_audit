'use strict';

const path = require('path');
const registerScriptsRoute = require('../../../../api/agent/routes/scripts');

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
      this.sendFileOptions = options;
      return this;
    },
  };
}

describe('scripts route', () => {
  function register(deps = {}) {
    const app = { get: jest.fn() };
    registerScriptsRoute(app, {
      scriptsDir: '/scripts',
      path,
      fsp: {
        stat: jest.fn(),
      },
      isWithinRoot: jest.fn(() => true),
      verboseRequestLog: jest.fn(),
      verboseResponseLog: jest.fn(),
      ...deps,
    });
    return { app, handler: app.get.mock.calls[0][1] };
  }

  test('rejects invalid script path segments', async () => {
    const { handler } = register();
    const res = createRes();

    await handler({ params: { name: '../bad.ela' } }, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid path\n');
  });

  test('returns not found when resolved path escapes the scripts root', async () => {
    const { handler } = register({
      isWithinRoot: jest.fn(() => false),
    });
    const res = createRes();

    await handler({ params: { name: 'good.ela' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });

  test('returns not found when script file is missing', async () => {
    const { handler } = register({
      fsp: {
        stat: jest.fn().mockRejectedValue(new Error('missing')),
      },
    });
    const res = createRes();

    await handler({ params: { name: 'missing.ela' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });

  test('serves an existing script file as text/plain', async () => {
    const stat = { isFile: () => true };
    const { handler } = register({
      fsp: {
        stat: jest.fn().mockResolvedValue(stat),
      },
    });
    const res = createRes();

    await handler({ params: { name: 'run.ela' } }, res);

    expect(res.headers['content-type']).toBe('text/plain');
    expect(res.sentFile).toBe('run.ela');
    expect(res.sendFileOptions).toEqual({ root: '/scripts' });
  });
});
