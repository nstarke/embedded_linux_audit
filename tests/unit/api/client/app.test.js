'use strict';

function loadCreateApp() {
  jest.resetModules();

  const app = { use: jest.fn(), get: jest.fn() };
  const expressFactory = jest.fn(() => app);

  const authMiddleware = jest.fn();
  const registerUploadsRoutes = jest.fn();
  const registerTerminalRoutes = jest.fn();
  const registerModuleBuildRoutes = jest.fn();
  const registerGhidraAnalysisRoutes = jest.fn();
  const registerSettingsRoutes = jest.fn();
  const rateLimiter = jest.fn();
  const swaggerServe = [jest.fn()];
  const swaggerSetupHandler = jest.fn();
  const swaggerUi = {
    serve: swaggerServe,
    setup: jest.fn(() => swaggerSetupHandler),
  };
  const openapiSpec = { openapi: '3.0.3' };

  jest.doMock('express-rate-limit', () => jest.fn(() => rateLimiter), { virtual: true });
  jest.doMock('express', () => expressFactory, { virtual: true });
  jest.doMock('swagger-ui-express', () => swaggerUi, { virtual: true });
  jest.doMock('../../../../api/auth', () => ({ middleware: authMiddleware }));
  jest.doMock('../../../../api/client/routes/uploads', () => registerUploadsRoutes);
  jest.doMock('../../../../api/client/routes/terminal', () => registerTerminalRoutes);
  jest.doMock('../../../../api/client/routes/moduleBuilds', () => registerModuleBuildRoutes);
  jest.doMock('../../../../api/client/routes/ghidraAnalysis', () => registerGhidraAnalysisRoutes);
  jest.doMock('../../../../api/client/routes/settings', () => registerSettingsRoutes);
  jest.doMock('../../../../api/client/openapi', () => ({ openapiSpec }));

  const { createApp } = require('../../../../api/client/app');
  return {
    app, createApp, authMiddleware, registerUploadsRoutes, registerTerminalRoutes,
    registerModuleBuildRoutes, registerGhidraAnalysisRoutes, registerSettingsRoutes, rateLimiter,
    swaggerUi, swaggerServe, swaggerSetupHandler, openapiSpec,
  };
}

function useFns(app) {
  return app.use.mock.calls.filter((c) => c.length === 1 && typeof c[0] === 'function').map((c) => c[0]);
}

describe('client app bootstrap', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('serves the OpenAPI spec and Swagger UI before auth, then the upload routes', () => {
    const {
      app, createApp, authMiddleware, registerUploadsRoutes, registerTerminalRoutes,
      registerModuleBuildRoutes, registerGhidraAnalysisRoutes, registerSettingsRoutes, rateLimiter,
      swaggerUi, swaggerServe, swaggerSetupHandler,
    } = loadCreateApp();

    const created = createApp();
    expect(created).toBe(app);

    // Rate limiting first.
    expect(app.use.mock.calls[0]).toEqual([rateLimiter]);

    // Public docs: GET /openapi.json and the /docs Swagger UI handlers. The UI
    // loads the spec by URL (not embedded) so dynamic servers are honored.
    const openapiRoute = app.get.mock.calls.find((c) => c[0] === '/openapi.json');
    expect(openapiRoute).toBeDefined();
    expect(swaggerUi.setup).toHaveBeenCalledWith(null, expect.objectContaining({
      swaggerOptions: expect.objectContaining({ url: '../openapi.json' }),
    }));
    const docsUse = app.use.mock.calls.find((c) => c[0] === '/docs');
    expect(docsUse).toEqual(['/docs', swaggerServe, swaggerSetupHandler]);

    // The docs UI must be registered before the auth middleware.
    const docsIdx = app.use.mock.calls.findIndex((c) => c[0] === '/docs');
    const authIdx = app.use.mock.calls.findIndex((c) => c[0] === authMiddleware);
    expect(docsIdx).toBeGreaterThanOrEqual(0);
    expect(authIdx).toBeGreaterThan(docsIdx);

    // Auth, then a user guard, then routes.
    expect(registerUploadsRoutes).toHaveBeenCalledWith(app, {});
    expect(registerTerminalRoutes).toHaveBeenCalledWith(app, {});
    expect(registerModuleBuildRoutes).toHaveBeenCalledWith(app, {});
    expect(registerGhidraAnalysisRoutes).toHaveBeenCalledWith(app, {});
    expect(registerSettingsRoutes).toHaveBeenCalledWith(app, {});
    const guard = useFns(app).find((fn) => fn !== rateLimiter && fn !== authMiddleware);
    expect(typeof guard).toBe('function');
  });

  test('GET /openapi.json sets the server base from X-Forwarded-Prefix', () => {
    const { app, createApp, openapiSpec } = loadCreateApp();
    createApp();
    const handler = app.get.mock.calls.find((c) => c[0] === '/openapi.json')[1];

    // Direct (no proxy prefix) -> root server.
    let res = { json: jest.fn() };
    handler({ headers: {} }, res);
    expect(res.json).toHaveBeenCalledWith({ ...openapiSpec, servers: [{ url: '/' }] });

    // Behind nginx -> the /client base (trailing slash trimmed).
    res = { json: jest.fn() };
    handler({ headers: { 'x-forwarded-prefix': '/client/' } }, res);
    expect(res.json).toHaveBeenCalledWith({ ...openapiSpec, servers: [{ url: '/client' }] });
  });

  test('the user guard rejects requests without a resolved user', () => {
    const { app, createApp, rateLimiter, authMiddleware } = loadCreateApp();
    createApp();
    const guard = useFns(app).find((fn) => fn !== rateLimiter && fn !== authMiddleware);

    const res = {
      statusCode: 200,
      body: undefined,
      status(code) { this.statusCode = code; return this; },
      json(value) { this.body = value; return this; },
    };
    const next = jest.fn();

    guard({ authUser: undefined }, res, next);
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({ error: 'Unauthorized' });
    expect(next).not.toHaveBeenCalled();
  });

  test('the user guard calls next when a user is resolved', () => {
    const { app, createApp, rateLimiter, authMiddleware } = loadCreateApp();
    createApp();
    const guard = useFns(app).find((fn) => fn !== rateLimiter && fn !== authMiddleware);

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    guard({ authUser: 'alice' }, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });
});
