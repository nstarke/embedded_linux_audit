'use strict';

const path = require('path');

function loadCreateApp() {
  jest.resetModules();

  const app = {
    use: jest.fn(),
  };
  const expressFactory = jest.fn(() => app);
  expressFactory.raw = jest.fn(() => 'raw-middleware');

  const authMiddleware = jest.fn();
  const registerRootRoute = jest.fn();
  const registerScriptsRoute = jest.fn();
  const registerTestsRoute = jest.fn();
  const registerUbootEnvRoute = jest.fn();
  const registerIsaRoute = jest.fn();
  const registerAssetRoute = jest.fn();
  const registerUploadRoute = jest.fn();
  const normalizeContentType = jest.fn();
  const sanitizeUploadPath = jest.fn();
  const writeUploadFile = jest.fn();
  const augmentJsonPayload = jest.fn();
  const logPathForContentType = jest.fn(() => 'wrapped-log-path');
  const isValidMacAddress = jest.fn();
  const isWithinRoot = jest.fn();
  const getClientIp = jest.fn(() => '127.0.0.1');

  jest.doMock('express', () => expressFactory, { virtual: true });
  jest.doMock('../../../../api/auth', () => ({ middleware: authMiddleware }));
  jest.doMock('../../../../api/agent/routes/root', () => registerRootRoute);
  jest.doMock('../../../../api/agent/routes/scripts', () => registerScriptsRoute);
  jest.doMock('../../../../api/agent/routes/tests', () => registerTestsRoute);
  jest.doMock('../../../../api/agent/routes/ubootEnv', () => registerUbootEnvRoute);
  jest.doMock('../../../../api/agent/routes/isa', () => registerIsaRoute);
  jest.doMock('../../../../api/agent/routes/assets', () => registerAssetRoute);
  jest.doMock('../../../../api/agent/routes/upload', () => registerUploadRoute);
  jest.doMock('../../../../api/agent/serverUtils', () => ({
    normalizeContentType,
    sanitizeUploadPath,
    writeUploadFile,
    augmentJsonPayload,
    logPathForContentType,
    isValidMacAddress,
    isWithinRoot,
    getClientIp,
  }));

  const { createApp } = require('../../../../api/agent/app');

  return {
    app,
    createApp,
    expressFactory,
    authMiddleware,
    registerRootRoute,
    registerScriptsRoute,
    registerTestsRoute,
    registerUbootEnvRoute,
    registerIsaRoute,
    registerAssetRoute,
    registerUploadRoute,
    logPathForContentType,
    getClientIp,
  };
}

describe('agent app bootstrap', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('registers raw-body and auth middleware, then wires all routes with shared deps', () => {
    const {
      app,
      createApp,
      expressFactory,
      authMiddleware,
      registerRootRoute,
      registerScriptsRoute,
      registerTestsRoute,
      registerUbootEnvRoute,
      registerIsaRoute,
      registerAssetRoute,
      registerUploadRoute,
      logPathForContentType,
    } = loadCreateApp();
    const persistUpload = jest.fn();

    const created = createApp({
      logPrefix: 'post_requests',
      assetsDir: '/srv/assets',
      dataDir: '/srv/data',
      testsDir: '/srv/tests',
      verbose: false,
      releaseStateFile: '/srv/state.json',
      validUploadTypes: new Set(['arch']),
      validContentTypes: { 'text/plain': 'text_plain' },
      persistUpload,
    });

    expect(created).toBe(app);
    expect(expressFactory).toHaveBeenCalledTimes(1);
    expect(expressFactory.raw).toHaveBeenCalledWith({ type: '*/*', limit: '100mb' });
    expect(app.use.mock.calls).toEqual([
      ['raw-middleware'],
      [authMiddleware],
    ]);

    const expectedDeps = registerRootRoute.mock.calls[0][1];
    expect(registerRootRoute).toHaveBeenCalledWith(app, expectedDeps);
    expect(registerScriptsRoute).toHaveBeenCalledWith(app, expectedDeps);
    expect(registerTestsRoute).toHaveBeenCalledWith(app, expectedDeps);
    expect(registerUbootEnvRoute).toHaveBeenCalledWith(app, expectedDeps);
    expect(registerIsaRoute).toHaveBeenCalledWith(app, expectedDeps);
    expect(registerUploadRoute).toHaveBeenCalledWith(app, expectedDeps);
    expect(registerAssetRoute).toHaveBeenCalledWith(app, expectedDeps);

    expect(expectedDeps.assetsDir).toBe('/srv/assets');
    expect(expectedDeps.testsDir).toBe('/srv/tests');
    expect(expectedDeps.scriptsDir).toBe(path.join('/srv/tests', 'scripts'));
    expect(expectedDeps.envDir).toBe(path.join('/srv/data', 'env'));
    expect(expectedDeps.dataDir).toBe('/srv/data');
    expect(expectedDeps.releaseStateFile).toBe('/srv/state.json');
    expect(expectedDeps.persistUpload).toBe(persistUpload);
    expect(expectedDeps.verboseRequestLog()).toBeUndefined();
    expect(expectedDeps.verboseResponseLog()).toBeUndefined();

    expect(expectedDeps.logPathForContentType('post_requests', 'text/plain')).toBe('wrapped-log-path');
    expect(logPathForContentType).toHaveBeenCalledWith(
      'post_requests',
      'text/plain',
      { 'text/plain': 'text_plain' },
    );
  });

  test('adds verbose request logging middleware when verbose mode is enabled', () => {
    const {
      app,
      createApp,
      getClientIp,
    } = loadCreateApp();
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});

    createApp({
      logPrefix: 'post_requests',
      assetsDir: '/srv/assets',
      dataDir: '/srv/data',
      testsDir: '/srv/tests',
      verbose: true,
      releaseStateFile: '/srv/state.json',
      validUploadTypes: new Set(['arch']),
      validContentTypes: { 'text/plain': 'text_plain' },
      persistUpload: jest.fn(),
    });

    expect(app.use).toHaveBeenCalledTimes(3);
    const verboseMiddleware = app.use.mock.calls[2][0];

    let finishHandler = null;
    const req = {
      method: 'POST',
      originalUrl: '/aa:bb/upload/arch',
    };
    const res = {
      statusCode: 201,
      on: jest.fn((event, handler) => {
        if (event === 'finish') {
          finishHandler = handler;
        }
      }),
      getHeader: jest.fn(() => '64'),
    };
    const next = jest.fn();

    verboseMiddleware(req, res, next);

    expect(getClientIp).toHaveBeenCalledWith(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.on).toHaveBeenCalledWith('finish', expect.any(Function));
    expect(logSpy).toHaveBeenCalledTimes(1);
    expect(logSpy.mock.calls[0][0]).toContain('127.0.0.1 POST /aa:bb/upload/arch');

    finishHandler();

    expect(logSpy).toHaveBeenCalledTimes(2);
    expect(logSpy.mock.calls[1][0]).toContain('127.0.0.1 POST /aa:bb/upload/arch -> 201 (64 bytes)');
  });
});
