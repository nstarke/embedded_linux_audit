'use strict';

// Keep this route unit test from transitively loading the real DB stack
// (clientUploads -> db/index -> sequelize). Route handlers receive their
// queries via deps, so the real module is never exercised here.
jest.mock('../../../../api/lib/db/clientUploads', () => ({
  listUploadTypesForUser: jest.fn(),
  listUploadsForUser: jest.fn(),
  getUploadForUser: jest.fn(),
}));

const registerUploadsRoutes = require('../../../../api/client/routes/uploads');

function createApp() {
  const handlers = {};
  return {
    handlers,
    get(routePath, handler) {
      handlers[routePath] = handler;
    },
  };
}

function createRes() {
  return {
    statusCode: 200,
    headers: {},
    body: undefined,
    jsonBody: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    type(value) {
      this.headers['content-type'] = value;
      return this;
    },
    json(value) {
      this.jsonBody = value;
      return this;
    },
    send(value) {
      this.body = value;
      return this;
    },
  };
}

function register(queries) {
  const app = createApp();
  registerUploadsRoutes(app, { queries });
  return app.handlers;
}

describe('client uploads routes', () => {
  test('GET /uploads returns upload types for the authenticated user', async () => {
    const listUploadTypesForUser = jest.fn().mockResolvedValue([{ uploadType: 'dmesg', count: 3 }]);
    const handlers = register({ listUploadTypesForUser });
    const res = createRes();

    await handlers['/uploads']({ authUser: 'alice', query: {} }, res);

    expect(listUploadTypesForUser).toHaveBeenCalledWith('alice');
    expect(res.jsonBody).toEqual({ uploadTypes: [{ uploadType: 'dmesg', count: 3 }] });
  });

  test('GET /uploads/:type rejects unknown upload types with 404', async () => {
    const listUploadsForUser = jest.fn();
    const handlers = register({ listUploadsForUser });
    const res = createRes();

    await handlers['/uploads/:type']({ authUser: 'alice', params: { type: 'bogus' }, query: {} }, res);

    expect(res.statusCode).toBe(404);
    expect(listUploadsForUser).not.toHaveBeenCalled();
  });

  test('GET /uploads/:type lists uploads with clamped limit/offset', async () => {
    const listUploadsForUser = jest.fn().mockResolvedValue([{ id: '1' }]);
    const handlers = register({ listUploadsForUser });
    const res = createRes();

    await handlers['/uploads/:type'](
      { authUser: 'alice', params: { type: 'dmesg' }, query: { limit: '5000', offset: '10' } },
      res,
    );

    expect(listUploadsForUser).toHaveBeenCalledWith('dmesg', 'alice', { limit: 1000, offset: 10 });
    expect(res.jsonBody).toEqual({ uploadType: 'dmesg', limit: 1000, offset: 10, uploads: [{ id: '1' }] });
  });

  test('GET /uploads/:type/:id returns 404 for non-numeric id', async () => {
    const getUploadForUser = jest.fn();
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:type/:id']({ authUser: 'alice', params: { type: 'dmesg', id: 'abc' } }, res);

    expect(res.statusCode).toBe(404);
    expect(getUploadForUser).not.toHaveBeenCalled();
  });

  test('GET /uploads/:type/:id returns the record when found', async () => {
    const record = { id: '12', uploadType: 'dmesg', payloadText: 'boot' };
    const getUploadForUser = jest.fn().mockResolvedValue(record);
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:type/:id']({ authUser: 'alice', params: { type: 'dmesg', id: '12' } }, res);

    expect(getUploadForUser).toHaveBeenCalledWith('dmesg', '12', 'alice');
    expect(res.jsonBody).toBe(record);
  });

  test('GET /uploads/:type/:id returns 404 when not owned/found', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue(null);
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:type/:id']({ authUser: 'mallory', params: { type: 'dmesg', id: '12' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.jsonBody).toEqual({ error: 'not found' });
  });

  test('GET /uploads/:type/:id/raw streams octet-stream payloads as bytes', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue({
      contentType: 'application/octet-stream',
      payloadBinary: Buffer.from([1, 2, 3]),
    });
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:type/:id/raw']({ authUser: 'alice', params: { type: 'file', id: '5' } }, res);

    expect(getUploadForUser).toHaveBeenCalledWith('file', '5', 'alice', { includeBinary: true });
    expect(res.headers['content-type']).toBe('application/octet-stream');
    expect(Buffer.isBuffer(res.body)).toBe(true);
    expect(Array.from(res.body)).toEqual([1, 2, 3]);
  });

  test('GET /uploads/:type/:id/raw returns stored text with its content type', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue({
      contentType: 'text/plain',
      payloadText: 'kernel: boot\n',
      payloadBinary: null,
    });
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:type/:id/raw']({ authUser: 'alice', params: { type: 'dmesg', id: '5' } }, res);

    expect(res.headers['content-type']).toBe('text/plain');
    expect(res.body).toBe('kernel: boot\n');
  });

  test('GET /uploads/:type uses default limit/offset when not supplied', async () => {
    const listUploadsForUser = jest.fn(async () => []);
    const handlers = register({ listUploadsForUser });
    const res = createRes();

    await handlers['/uploads/:type']({ authUser: 'alice', params: { type: 'dmesg' }, query: {} }, res);

    expect(listUploadsForUser).toHaveBeenCalledWith('dmesg', 'alice', { limit: 100, offset: 0 });
    expect(res.jsonBody).toEqual({ uploadType: 'dmesg', limit: 100, offset: 0, uploads: [] });
  });

  test('GET /uploads/:type/:id/raw returns 404 for invalid type or id', async () => {
    const getUploadForUser = jest.fn();
    const handlers = register({ getUploadForUser });

    const resBadType = createRes();
    await handlers['/uploads/:type/:id/raw']({ authUser: 'alice', params: { type: 'bogus', id: '5' } }, resBadType);
    expect(resBadType.statusCode).toBe(404);

    const resBadId = createRes();
    await handlers['/uploads/:type/:id/raw']({ authUser: 'alice', params: { type: 'dmesg', id: 'abc' } }, resBadId);
    expect(resBadId.statusCode).toBe(404);

    expect(getUploadForUser).not.toHaveBeenCalled();
  });

  test('GET /uploads/:type/:id/raw returns 404 when the artifact is not found', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue(null);
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:type/:id/raw']({ authUser: 'alice', params: { type: 'dmesg', id: '5' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.jsonBody).toEqual({ error: 'not found' });
  });

  test('GET /uploads/:type/:id/raw serves stored JSON payloads', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue({
      contentType: 'application/json',
      payloadText: null,
      payloadJson: { a: 1 },
      payloadBinary: null,
    });
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:type/:id/raw']({ authUser: 'alice', params: { type: 'cmd', id: '5' } }, res);

    expect(res.headers['content-type']).toBe('application/json');
    expect(res.body).toBe(JSON.stringify({ a: 1 }));
  });

  test('GET /uploads/:type/:id/raw 404s when no raw payload is stored', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue({
      contentType: 'text/plain',
      payloadText: null,
      payloadJson: null,
      payloadBinary: null,
    });
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:type/:id/raw']({ authUser: 'alice', params: { type: 'dmesg', id: '5' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.jsonBody).toEqual({ error: 'no raw payload stored for this upload' });
  });
});
