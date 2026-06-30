'use strict';

const { EventEmitter } = require('events');
const { createTerminalHttpHandler } = require('../../../../api/terminal/httpRoutes');

function createMockResponse() {
  return {
    statusCode: null,
    headers: null,
    body: null,
    writeHead(statusCode, headers) {
      this.statusCode = statusCode;
      this.headers = headers;
    },
    end(body) {
      this.body = body;
    },
  };
}

// A request object that is also an EventEmitter so the JSON body reader works.
function createMockRequest({ method = 'GET', url = '/', headers = {}, body = null } = {}) {
  const req = new EventEmitter();
  req.method = method;
  req.url = url;
  req.headers = headers;
  req.socket = { remoteAddress: '127.0.0.1' };
  // Emit the body on the next tick so handlers can attach listeners first.
  process.nextTick(() => {
    if (body !== null) {
      req.emit('data', typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.emit('end');
  });
  return req;
}

function waitForResponse(res) {
  return new Promise((resolve) => {
    const originalEnd = res.end.bind(res);
    res.end = (body) => {
      originalEnd(body);
      resolve(res);
    };
  });
}

function createRegistry(entries) {
  const map = new Map(entries);
  return {
    entries: () => [...map.entries()],
    getSession: (mac) => map.get(mac),
  };
}

describe('terminal HTTP routes', () => {
  test('returns ok for the healthcheck route', () => {
    const handler = createTerminalHttpHandler();
    const res = createMockResponse();

    handler({ method: 'GET', url: '/terminal/healthcheck' }, res);

    expect(res.statusCode).toBe(200);
    expect(res.headers).toEqual({ 'Content-Type': 'text/plain; charset=utf-8' });
    expect(res.body).toBe('ok');
  });

  test('returns 404 for unknown routes', () => {
    const handler = createTerminalHttpHandler();
    const res = createMockResponse();

    handler({ method: 'GET', url: '/terminal/unknown' }, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('Not Found');
  });

  describe('GET /terminal/sessions', () => {
    test('returns the active sessions as JSON', () => {
      const sessionRegistry = createRegistry([
        ['aa:bb:cc:dd:ee:ff', {
          alias: 'router',
          group: 'home',
          remoteAddress: '10.0.0.5',
          connectedAt: '2026-06-29T00:00:00.000Z',
          lastHeartbeat: '2026-06-29T00:01:00.000Z',
        }],
      ]);
      const handler = createTerminalHttpHandler({ sessionRegistry });
      const res = createMockResponse();

      handler({ method: 'GET', url: '/terminal/sessions', headers: {}, socket: {} }, res);

      expect(res.statusCode).toBe(200);
      expect(res.headers).toEqual({ 'Content-Type': 'application/json; charset=utf-8' });
      expect(JSON.parse(res.body)).toEqual([
        {
          mac: 'aa:bb:cc:dd:ee:ff',
          alias: 'router',
          group: 'home',
          remoteAddress: '10.0.0.5',
          connectedAt: '2026-06-29T00:00:00.000Z',
          lastHeartbeat: '2026-06-29T00:01:00.000Z',
        },
      ]);
    });

    test('rejects unauthorized requests', () => {
      const sessionRegistry = createRegistry([]);
      const auth = { checkBearer: () => false };
      const handler = createTerminalHttpHandler({ sessionRegistry, auth });
      const res = createMockResponse();

      handler({ method: 'GET', url: '/terminal/sessions', headers: {}, socket: {} }, res);

      expect(res.statusCode).toBe(401);
      expect(JSON.parse(res.body)).toEqual({ error: 'Unauthorized' });
    });
  });

  describe('POST /terminal/:mac/exec', () => {
    const mac = 'aa:bb:cc:dd:ee:ff';

    test('runs the command and returns its output', async () => {
      const entry = { ws: {} };
      const sessionRegistry = createRegistry([[mac, entry]]);
      const runExecImpl = jest.fn().mockResolvedValue({ output: 'hello\n', durationMs: 42 });
      const handler = createTerminalHttpHandler({ sessionRegistry, runExecImpl });
      const res = createMockResponse();
      const done = waitForResponse(res);

      handler(
        createMockRequest({ method: 'POST', url: `/terminal/${mac}/exec`, body: { command: 'echo hello' } }),
        res,
      );
      await done;

      expect(runExecImpl).toHaveBeenCalledWith({ entry, mac, command: 'echo hello', timeoutMs: undefined });
      expect(res.statusCode).toBe(200);
      expect(JSON.parse(res.body)).toEqual({ ok: true, output: 'hello\n', durationMs: 42 });
    });

    test('passes through a custom timeoutMs', async () => {
      const entry = { ws: {} };
      const sessionRegistry = createRegistry([[mac, entry]]);
      const runExecImpl = jest.fn().mockResolvedValue({ output: '', durationMs: 1 });
      const handler = createTerminalHttpHandler({ sessionRegistry, runExecImpl });
      const res = createMockResponse();
      const done = waitForResponse(res);

      handler(
        createMockRequest({ method: 'POST', url: `/terminal/${mac}/exec`, body: { command: 'sleep 1', timeoutMs: 5000 } }),
        res,
      );
      await done;

      expect(runExecImpl).toHaveBeenCalledWith({ entry, mac, command: 'sleep 1', timeoutMs: 5000 });
    });

    test('returns 404 when there is no session for the mac', async () => {
      const sessionRegistry = createRegistry([]);
      const handler = createTerminalHttpHandler({ sessionRegistry, runExecImpl: jest.fn() });
      const res = createMockResponse();
      const done = waitForResponse(res);

      handler(
        createMockRequest({ method: 'POST', url: `/terminal/${mac}/exec`, body: { command: 'ls' } }),
        res,
      );
      await done;

      expect(res.statusCode).toBe(404);
      expect(JSON.parse(res.body)).toEqual({ error: 'no active session for mac' });
    });

    test('returns 504 when the exec times out', async () => {
      const entry = { ws: {} };
      const sessionRegistry = createRegistry([[mac, entry]]);
      const runExecImpl = jest.fn().mockRejectedValue(
        Object.assign(new Error('exec timed out'), { code: 'TIMEOUT', output: 'partial', durationMs: 9000 }),
      );
      const handler = createTerminalHttpHandler({ sessionRegistry, runExecImpl });
      const res = createMockResponse();
      const done = waitForResponse(res);

      handler(
        createMockRequest({ method: 'POST', url: `/terminal/${mac}/exec`, body: { command: 'sleep 99' } }),
        res,
      );
      await done;

      expect(res.statusCode).toBe(504);
      expect(JSON.parse(res.body)).toEqual({
        ok: false,
        error: 'exec timed out',
        output: 'partial',
        durationMs: 9000,
      });
    });

    test('rejects a missing command with 400', async () => {
      const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
      const handler = createTerminalHttpHandler({ sessionRegistry, runExecImpl: jest.fn() });
      const res = createMockResponse();
      const done = waitForResponse(res);

      handler(
        createMockRequest({ method: 'POST', url: `/terminal/${mac}/exec`, body: {} }),
        res,
      );
      await done;

      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body)).toEqual({ error: 'command is required' });
    });

    test('rejects an invalid mac with 400', async () => {
      const sessionRegistry = createRegistry([]);
      const handler = createTerminalHttpHandler({ sessionRegistry, runExecImpl: jest.fn() });
      const res = createMockResponse();
      const done = waitForResponse(res);

      handler(
        createMockRequest({ method: 'POST', url: '/terminal/not-a-mac/exec', body: { command: 'ls' } }),
        res,
      );
      await done;

      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body)).toEqual({ error: 'invalid mac address' });
    });

    test('rejects unauthorized exec requests', () => {
      const sessionRegistry = createRegistry([[mac, { ws: {} }]]);
      const auth = { checkBearer: () => false };
      const handler = createTerminalHttpHandler({ sessionRegistry, auth, runExecImpl: jest.fn() });
      const res = createMockResponse();

      handler({ method: 'POST', url: `/terminal/${mac}/exec`, headers: {}, socket: {} }, res);

      expect(res.statusCode).toBe(401);
      expect(JSON.parse(res.body)).toEqual({ error: 'Unauthorized' });
    });
  });
});
