'use strict';

const path = require('path');
const registerTestsRoute = require('../../../../api/agent/routes/tests');

function createRes() {
  return {
    statusCode: 200,
    headers: {},
    body: '',
    headersSent: false,
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
      this.headersSent = true;
      return this;
    },
    sendFile(value, cb) {
      this.sentFile = value;
      this.headersSent = true;
      if (cb) {
        cb();
      }
      return this;
    },
  };
}

describe('tests route', () => {
  function register(deps = {}) {
    const app = { get: jest.fn() };
    registerTestsRoute(app, {
      testsDir: '/configured/tests',
      path,
      fsp: {
        stat: jest.fn(),
        access: jest.fn(),
      },
      isWithinRoot: jest.fn(() => true),
      verboseRequestLog: jest.fn(),
      verboseResponseLog: jest.fn(),
      ...deps,
    });
    return {
      app,
      exactHandler: app.get.mock.calls[0][1],
      regexHandler: app.get.mock.calls[1][1],
    };
  }

  test('serves configured shell tests from the explicit route', async () => {
    const configuredShell = path.join('/configured/tests', 'agent', 'shell', 'basic.sh');
    const { exactHandler } = register({
      fsp: {
        stat: jest.fn(async (candidate) => {
          if (candidate === configuredShell) {
            return { isFile: () => true };
          }
          throw new Error('missing');
        }),
        access: jest.fn(),
      },
    });
    const res = createRes();

    await exactHandler({ params: { type: 'shell', scriptName: 'basic.sh' } }, res);

    expect(res.sentFile).toBe(configuredShell);
  });

  test('falls back to repo scripts for nested script paths served by the regex route', async () => {
    const configuredScripts = path.join('/configured/tests', 'agent', 'scripts', 'nested', 'sample.ela');
    const repoScripts = path.resolve(__dirname, '../../../../tests/agent/scripts/nested/sample.ela');
    const { regexHandler } = register({
      fsp: {
        stat: jest.fn(async (candidate) => {
          if (candidate === configuredScripts) {
            throw new Error('missing');
          }
          if (candidate === repoScripts) {
            return { isFile: () => true };
          }
          throw new Error(`unexpected ${candidate}`);
        }),
        access: jest.fn(),
      },
    });
    const res = createRes();

    await regexHandler({ params: ['scripts', 'nested/sample.ela'] }, res);

    expect(res.sentFile).toBe(repoScripts);
  });

  test('rejects traversal paths', async () => {
    const { regexHandler } = register();
    const res = createRes();

    await regexHandler({ params: ['shell', '../escape.sh'] }, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid path\n');
  });

  test('returns not found when no candidate test file exists', async () => {
    const { exactHandler } = register({
      fsp: {
        stat: jest.fn().mockRejectedValue(new Error('missing')),
        access: jest.fn(),
      },
    });
    const res = createRes();

    await exactHandler({ params: { type: 'scripts', scriptName: 'missing.ela' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });
});
