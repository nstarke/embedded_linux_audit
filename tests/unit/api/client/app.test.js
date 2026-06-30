'use strict';

function loadCreateApp() {
  jest.resetModules();

  const app = { use: jest.fn() };
  const expressFactory = jest.fn(() => app);

  const authMiddleware = jest.fn();
  const registerUploadsRoutes = jest.fn();
  const rateLimiter = jest.fn();

  jest.doMock('express-rate-limit', () => jest.fn(() => rateLimiter), { virtual: true });
  jest.doMock('express', () => expressFactory, { virtual: true });
  jest.doMock('../../../../api/auth', () => ({ middleware: authMiddleware }));
  jest.doMock('../../../../api/client/routes/uploads', () => registerUploadsRoutes);

  const { createApp } = require('../../../../api/client/app');
  return { app, createApp, expressFactory, authMiddleware, registerUploadsRoutes, rateLimiter };
}

describe('client app bootstrap', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('wires rate-limit, auth, a user guard, then the upload routes', () => {
    const { app, createApp, authMiddleware, registerUploadsRoutes, rateLimiter } = loadCreateApp();

    const created = createApp();

    expect(created).toBe(app);
    expect(app.use.mock.calls[0]).toEqual([rateLimiter]);
    expect(app.use.mock.calls[1]).toEqual([authMiddleware]);
    expect(typeof app.use.mock.calls[2][0]).toBe('function');
    expect(registerUploadsRoutes).toHaveBeenCalledWith(app, {});
  });

  test('the user guard rejects requests without a resolved user', () => {
    const { app, createApp } = loadCreateApp();
    createApp();
    const guard = app.use.mock.calls[2][0];

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
    const { app, createApp } = loadCreateApp();
    createApp();
    const guard = app.use.mock.calls[2][0];

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
