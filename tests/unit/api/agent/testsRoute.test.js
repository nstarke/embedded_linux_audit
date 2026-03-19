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
      commonRedactionHandler: app.get.mock.calls[2][1],
      catchallHandler: app.get.mock.calls[3][1],
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

  test('returns 400 "invalid request" when type or path is not a string', async () => {
    const { exactHandler } = register();
    const res = createRes();

    await exactHandler({ params: { type: null, scriptName: 'basic.sh' } }, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid request\n');
  });

  test('returns 400 "invalid type" for an unrecognised test type', async () => {
    const { exactHandler } = register();
    const res = createRes();

    await exactHandler({ params: { type: 'unknown', scriptName: 'something.ela' } }, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid type\n');
  });

  test('returns 400 "invalid path" when the file extension does not match the type', async () => {
    const { exactHandler } = register();
    const res = createRes();

    // type is 'shell' so expected suffix is .sh, but .ela is given
    await exactHandler({ params: { type: 'shell', scriptName: 'basic.ela' } }, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid path\n');
  });

  test('returns 404 when isWithinRoot rejects all candidates', async () => {
    const { exactHandler } = register({
      isWithinRoot: jest.fn(() => false),
    });
    const res = createRes();

    await exactHandler({ params: { type: 'shell', scriptName: 'basic.sh' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });

  test('skips a candidate that exists but is not a file', async () => {
    const repoShell = path.resolve(__dirname, '../../../../tests/agent/shell/basic.sh');
    const { exactHandler } = register({
      fsp: {
        stat: jest.fn(async (candidate) => {
          if (candidate === repoShell) {
            return { isFile: () => true };
          }
          // configured dir candidate: exists but is a directory
          return { isFile: () => false };
        }),
        access: jest.fn(),
      },
    });
    const res = createRes();

    await exactHandler({ params: { type: 'shell', scriptName: 'basic.sh' } }, res);

    expect(res.sentFile).toBe(repoShell);
  });

  test('returns 500 from sendFile error callback when headers have not been sent', async () => {
    const configuredShell = path.join('/configured/tests', 'agent', 'shell', 'basic.sh');
    const { exactHandler } = register({
      fsp: {
        stat: jest.fn().mockResolvedValue({ isFile: () => true }),
        access: jest.fn(),
      },
    });
    const res = createRes();
    res.sendFile = (filePath, cb) => {
      res.sentFile = filePath;
      // headers not yet sent; simulate a sendFile transport error
      if (cb) cb(new Error('send error'));
    };

    await exactHandler({ params: { type: 'shell', scriptName: 'basic.sh' } }, res);

    expect(res.sentFile).toBe(configuredShell);
    expect(res.statusCode).toBe(500);
    expect(res.body).toBe('internal error\n');
  });

  test('returns 500 from the exact route outer catch when sendAgentTest throws', async () => {
    const { exactHandler } = register({
      verboseRequestLog: jest.fn(() => { throw new Error('log error'); }),
    });
    const res = createRes();

    await exactHandler({ params: { type: 'shell', scriptName: 'basic.sh' } }, res);

    expect(res.statusCode).toBe(500);
    expect(res.body).toBe('internal error\n');
  });

  test('returns 500 from the regex route outer catch when sendAgentTest throws', async () => {
    const { regexHandler } = register({
      verboseRequestLog: jest.fn(() => { throw new Error('log error'); }),
    });
    const res = createRes();

    await regexHandler({ params: ['shell', 'basic.sh'] }, res);

    expect(res.statusCode).toBe(500);
    expect(res.body).toBe('internal error\n');
  });

  test('common_redaction.sh route serves the file when it exists', async () => {
    const { commonRedactionHandler } = register({
      fsp: {
        stat: jest.fn(),
        access: jest.fn().mockResolvedValue(undefined),
      },
    });
    const res = createRes();

    await commonRedactionHandler({}, res);

    expect(res.sentFile).toMatch(/common_redaction\.sh$/);
  });

  test('common_redaction.sh route returns 404 when the file is not accessible', async () => {
    const { commonRedactionHandler } = register({
      fsp: {
        stat: jest.fn(),
        access: jest.fn().mockRejectedValue(new Error('ENOENT')),
      },
    });
    const res = createRes();

    await commonRedactionHandler({}, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });

  test('common_redaction.sh route returns 500 from sendFile error callback', async () => {
    const { commonRedactionHandler } = register({
      fsp: {
        stat: jest.fn(),
        access: jest.fn().mockResolvedValue(undefined),
      },
    });
    const res = createRes();
    res.sendFile = (filePath, cb) => {
      res.sentFile = filePath;
      if (cb) cb(new Error('send error'));
    };

    await commonRedactionHandler({}, res);

    expect(res.statusCode).toBe(500);
    expect(res.body).toBe('internal error\n');
  });

  test('catch-all /tests/* route returns 404 for any unmatched path', async () => {
    const { catchallHandler } = register();
    const res = createRes();

    await catchallHandler({}, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('not found\n');
  });
});
