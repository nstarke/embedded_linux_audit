'use strict';

const path = require('path');
const registerUbootEnvRoute = require('../../../../api/agent/routes/ubootEnv');

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

describe('uboot env route', () => {
  function register(deps = {}) {
    const app = { get: jest.fn() };
    registerUbootEnvRoute(app, {
      envDir: '/env',
      path,
      fsp: {
        stat: jest.fn(),
      },
      isWithinRoot: jest.fn(() => true),
      verboseRequestLog: jest.fn(),
      verboseResponseLog: jest.fn(),
      ...deps,
    });
    return app.get.mock.calls[0][1];
  }

  test('serves an existing env file', async () => {
    const handler = register({
      fsp: {
        stat: jest.fn().mockResolvedValue({ isFile: () => true }),
      },
    });
    const res = createRes();

    await handler({ params: { env_filename: 'prod.env' } }, res);

    expect(res.sentFile).toBe(path.resolve('/env', 'prod.env'));
  });

  test('rejects resolved paths outside the env directory', async () => {
    const handler = register({
      isWithinRoot: jest.fn(() => false),
    });
    const res = createRes();

    await handler({ params: { env_filename: '../escape.env' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });

  test('returns not found when env file is missing', async () => {
    const handler = register({
      fsp: {
        stat: jest.fn().mockRejectedValue(new Error('missing')),
      },
    });
    const res = createRes();

    await handler({ params: { env_filename: 'missing.env' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });
});
