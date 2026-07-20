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

    expect(listUploadTypesForUser).toHaveBeenCalledWith('alice', { mac: null });
    expect(res.jsonBody).toEqual({ uploadTypes: [{ uploadType: 'dmesg', count: 3 }] });
  });

  test('GET /uploads?type= rejects unknown upload types with 400', async () => {
    const listUploadsForUser = jest.fn();
    const handlers = register({ listUploadsForUser });
    const res = createRes();

    await handlers['/uploads']({ authUser: 'alice', query: { type: 'bogus' } }, res);

    expect(res.statusCode).toBe(400);
    expect(listUploadsForUser).not.toHaveBeenCalled();
  });

  test('GET /uploads?type= lists uploads with clamped limit/offset', async () => {
    const listUploadsForUser = jest.fn().mockResolvedValue([{ id: '1' }]);
    const handlers = register({ listUploadsForUser });
    const res = createRes();

    await handlers['/uploads'](
      { authUser: 'alice', query: { type: 'dmesg', limit: '5000', offset: '10' } },
      res,
    );

    expect(listUploadsForUser).toHaveBeenCalledWith('dmesg', 'alice', { limit: 1000, offset: 10, mac: null });
    expect(res.jsonBody).toEqual({ uploadType: 'dmesg', limit: 1000, offset: 10, uploads: [{ id: '1' }] });
  });

  test('GET /uploads passes a mac filter through and 400s an invalid one', async () => {
    const listUploadTypesForUser = jest.fn().mockResolvedValue([]);
    const handlers = register({ listUploadTypesForUser });

    // Valid mac (any separator) is forwarded verbatim; the query layer canonicalizes.
    const okRes = createRes();
    await handlers['/uploads']({ authUser: 'alice', query: { mac: 'AA-BB-CC-DD-EE-FF' } }, okRes);
    expect(listUploadTypesForUser).toHaveBeenCalledWith('alice', { mac: 'AA-BB-CC-DD-EE-FF' });
    expect(okRes.statusCode).toBe(200);

    // Malformed mac -> 400, query not run.
    listUploadTypesForUser.mockClear();
    const badRes = createRes();
    await handlers['/uploads']({ authUser: 'alice', query: { mac: 'nope' } }, badRes);
    expect(badRes.statusCode).toBe(400);
    expect(listUploadTypesForUser).not.toHaveBeenCalled();
  });

  test('GET /uploads?type= forwards the mac filter and echoes it in the body', async () => {
    const listUploadsForUser = jest.fn().mockResolvedValue([{ id: '1' }]);
    const handlers = register({ listUploadsForUser });
    const res = createRes();

    await handlers['/uploads'](
      { authUser: 'alice', query: { type: 'dmesg', mac: '20:4c:03:32:75:5c' } },
      res,
    );

    expect(listUploadsForUser).toHaveBeenCalledWith('dmesg', 'alice', { limit: 100, offset: 0, mac: '20:4c:03:32:75:5c' });
    expect(res.jsonBody).toEqual({
      uploadType: 'dmesg', limit: 100, offset: 0, mac: '20:4c:03:32:75:5c', uploads: [{ id: '1' }],
    });
  });

  test('GET /uploads/:id returns 404 for non-numeric id', async () => {
    const getUploadForUser = jest.fn();
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:id']({ authUser: 'alice', params: { id: 'abc' } }, res);

    expect(res.statusCode).toBe(404);
    expect(getUploadForUser).not.toHaveBeenCalled();
  });

  test('GET /uploads/:id returns the record when found', async () => {
    const record = { id: '12', uploadType: 'dmesg', payloadText: 'boot' };
    const getUploadForUser = jest.fn().mockResolvedValue(record);
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:id']({ authUser: 'alice', params: { id: '12' } }, res);

    expect(getUploadForUser).toHaveBeenCalledWith('12', 'alice');
    expect(res.jsonBody).toBe(record);
  });

  test('GET /uploads/:id returns 404 when not owned/found', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue(null);
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:id']({ authUser: 'mallory', params: { id: '12' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.jsonBody).toEqual({ error: 'not found' });
  });

  test('GET /uploads/:id/raw streams octet-stream payloads as bytes', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue({
      contentType: 'application/octet-stream',
      payloadBinary: Buffer.from([1, 2, 3]),
    });
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:id/raw']({ authUser: 'alice', params: { id: '5' } }, res);

    expect(getUploadForUser).toHaveBeenCalledWith('5', 'alice', { includeBinary: true });
    expect(res.headers['content-type']).toBe('application/octet-stream');
    expect(Buffer.isBuffer(res.body)).toBe(true);
    expect(Array.from(res.body)).toEqual([1, 2, 3]);
  });

  test('GET /uploads/:id/raw returns stored text with its content type', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue({
      contentType: 'text/plain',
      payloadText: 'kernel: boot\n',
      payloadBinary: null,
    });
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:id/raw']({ authUser: 'alice', params: { id: '5' } }, res);

    expect(res.headers['content-type']).toBe('text/plain');
    expect(res.body).toBe('kernel: boot\n');
  });

  test('GET /uploads?type= uses default limit/offset when not supplied', async () => {
    const listUploadsForUser = jest.fn(async () => []);
    const handlers = register({ listUploadsForUser });
    const res = createRes();

    await handlers['/uploads']({ authUser: 'alice', query: { type: 'dmesg' } }, res);

    expect(listUploadsForUser).toHaveBeenCalledWith('dmesg', 'alice', { limit: 100, offset: 0, mac: null });
    expect(res.jsonBody).toEqual({ uploadType: 'dmesg', limit: 100, offset: 0, uploads: [] });
  });

  test('GET /uploads/:id/raw returns 404 for an invalid id', async () => {
    const getUploadForUser = jest.fn();
    const handlers = register({ getUploadForUser });

    const resBadId = createRes();
    await handlers['/uploads/:id/raw']({ authUser: 'alice', params: { id: 'abc' } }, resBadId);
    expect(resBadId.statusCode).toBe(404);

    expect(getUploadForUser).not.toHaveBeenCalled();
  });

  test('GET /uploads/:id/raw returns 404 when the artifact is not found', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue(null);
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:id/raw']({ authUser: 'alice', params: { id: '5' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.jsonBody).toEqual({ error: 'not found' });
  });

  test('GET /uploads/:id/raw serves stored JSON payloads', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue({
      contentType: 'application/json',
      payloadText: null,
      payloadJson: { a: 1 },
      payloadBinary: null,
    });
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:id/raw']({ authUser: 'alice', params: { id: '5' } }, res);

    expect(res.headers['content-type']).toBe('application/json');
    expect(res.body).toBe(JSON.stringify({ a: 1 }));
  });

  test('GET /uploads/:id/raw 404s when no raw payload is stored', async () => {
    const getUploadForUser = jest.fn().mockResolvedValue({
      contentType: 'text/plain',
      payloadText: null,
      payloadJson: null,
      payloadBinary: null,
    });
    const handlers = register({ getUploadForUser });
    const res = createRes();

    await handlers['/uploads/:id/raw']({ authUser: 'alice', params: { id: '5' } }, res);

    expect(res.statusCode).toBe(404);
    expect(res.jsonBody).toEqual({ error: 'no raw payload stored for this upload' });
  });
});
