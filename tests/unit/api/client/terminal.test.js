'use strict';

const registerTerminalRoutes = require('../../../../api/client/routes/terminal');

// Minimal express-like app that records handlers and lets us invoke a route's
// full middleware chain in order (mirrors how express runs them).
function createApp() {
  const routes = [];
  const record = (method) => (path, ...chain) => routes.push({ method, path, chain });
  return {
    routes,
    get: record('get'),
    post: record('post'),
    delete: record('delete'),
    find(method, path) {
      return routes.find((r) => r.method === method && r.path === path);
    },
  };
}

function createRes() {
  return {
    statusCode: 200,
    body: undefined,
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; },
  };
}

// Run a route's chain (middlewares + handler), stopping if one responds without
// calling next(). `express.json` bodies are pre-set on req.body by the caller.
async function invoke(route, req, res) {
  const chain = route.chain.filter((fn) => typeof fn === 'function');
  for (const fn of chain) {
    // Skip the express.json body parser (identified by arity/parser signature):
    // tests set req.body directly.
    if (fn.name === 'jsonParser') continue;
    let advanced = false;
    // eslint-disable-next-line no-await-in-loop
    await fn(req, res, () => { advanced = true; });
    if (!advanced) return;
  }
}

function setup(overrides = {}) {
  const app = createApp();
  const deps = {
    sendCommand: jest.fn().mockResolvedValue({ status: 200, body: { ok: true } }),
    isUserAssociatedWithDevice: jest.fn().mockResolvedValue(true),
    listUserDeviceMacs: jest.fn().mockResolvedValue([]),
    ...overrides,
  };
  registerTerminalRoutes(app, deps);
  return { app, deps };
}

const MAC = 'aa:bb:cc:dd:ee:ff';

describe('client terminal routes', () => {
  describe('GET /terminal/sessions', () => {
    test('lists only the caller\'s associated devices', async () => {
      const { app, deps } = setup({
        listUserDeviceMacs: jest.fn().mockResolvedValue([MAC]),
        sendCommand: jest.fn().mockResolvedValue({
          status: 200,
          body: { sessions: [{ mac: MAC }, { mac: '11:22:33:44:55:66' }] },
        }),
      });
      const res = createRes();
      await invoke(app.find('get', '/terminal/sessions'), { authUser: 'alice' }, res);

      expect(deps.sendCommand).toHaveBeenCalledWith({ type: 'sessions' }, expect.any(Object));
      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual({ sessions: [{ mac: MAC }] });
    });

    test('504 when the terminal worker does not answer', async () => {
      const { app } = setup({
        listUserDeviceMacs: jest.fn().mockResolvedValue([MAC]),
        sendCommand: jest.fn().mockRejectedValue(new Error('timed out')),
      });
      const res = createRes();
      await invoke(app.find('get', '/terminal/sessions'), { authUser: 'alice' }, res);
      expect(res.statusCode).toBe(504);
    });
  });

  describe('ACL on per-device routes', () => {
    test('a non-associated device is 404 and never enqueues a command', async () => {
      const { app, deps } = setup({ isUserAssociatedWithDevice: jest.fn().mockResolvedValue(false) });
      const res = createRes();
      await invoke(app.find('post', '/terminal/:mac/exec'), { authUser: 'mallory', params: { mac: MAC }, body: { command: 'id' } }, res);

      expect(deps.isUserAssociatedWithDevice).toHaveBeenCalledWith('mallory', MAC);
      expect(res.statusCode).toBe(404);
      expect(res.body).toEqual({ error: 'no active session for mac' });
      expect(deps.sendCommand).not.toHaveBeenCalled();
    });

    test('an invalid MAC is 400 before any association check', async () => {
      const { app, deps } = setup();
      const res = createRes();
      await invoke(app.find('post', '/terminal/:mac/exec'), { authUser: 'alice', params: { mac: 'not-a-mac' }, body: { command: 'id' } }, res);
      expect(res.statusCode).toBe(400);
      expect(deps.isUserAssociatedWithDevice).not.toHaveBeenCalled();
    });

    test('a 500 from the association lookup surfaces as 500', async () => {
      const { app } = setup({ isUserAssociatedWithDevice: jest.fn().mockRejectedValue(new Error('db down')) });
      const res = createRes();
      await invoke(app.find('get', '/terminal/:mac/spawn'), { authUser: 'alice', params: { mac: MAC } }, res);
      expect(res.statusCode).toBe(500);
    });
  });

  describe('exec', () => {
    test('requires a command', async () => {
      const { app, deps } = setup();
      const res = createRes();
      await invoke(app.find('post', '/terminal/:mac/exec'), { authUser: 'alice', params: { mac: MAC }, body: {} }, res);
      expect(res.statusCode).toBe(400);
      expect(deps.sendCommand).not.toHaveBeenCalled();
    });

    test('rejects an out-of-range timeoutMs', async () => {
      const { app } = setup();
      const res = createRes();
      await invoke(app.find('post', '/terminal/:mac/exec'), { authUser: 'alice', params: { mac: MAC }, body: { command: 'id', timeoutMs: 99999 } }, res);
      expect(res.statusCode).toBe(400);
    });

    test('enqueues an exec command and relays the worker result', async () => {
      const { app, deps } = setup({
        sendCommand: jest.fn().mockResolvedValue({ status: 200, body: { ok: true, output: 'uid=0', durationMs: 4 } }),
      });
      const res = createRes();
      await invoke(app.find('post', '/terminal/:mac/exec'), { authUser: 'alice', params: { mac: MAC }, body: { command: 'id', timeoutMs: 2000 } }, res);

      expect(deps.sendCommand).toHaveBeenCalledWith(
        { type: 'exec', mac: MAC, command: 'id', timeoutMs: 2000 },
        { waitMs: 12000 },
      );
      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual({ ok: true, output: 'uid=0', durationMs: 4 });
    });
  });

  describe('spawn / kill', () => {
    test('validates args and port, then enqueues spawn', async () => {
      const { app, deps } = setup({ sendCommand: jest.fn().mockResolvedValue({ status: 201, body: { pid: 7 } }) });

      const badArgs = createRes();
      await invoke(app.find('post', '/terminal/:mac/spawn'), { authUser: 'alice', params: { mac: MAC }, body: { command: 'x', args: [1] } }, badArgs);
      expect(badArgs.statusCode).toBe(400);

      const badPort = createRes();
      await invoke(app.find('post', '/terminal/:mac/spawn'), { authUser: 'alice', params: { mac: MAC }, body: { command: 'x', port: 70000 } }, badPort);
      expect(badPort.statusCode).toBe(400);

      const ok = createRes();
      await invoke(app.find('post', '/terminal/:mac/spawn'), { authUser: 'alice', params: { mac: MAC }, body: { command: 'gdbserver', args: ['a'], port: 1234 } }, ok);
      expect(deps.sendCommand).toHaveBeenLastCalledWith(
        { type: 'spawn', mac: MAC, command: 'gdbserver', args: ['a'], port: 1234 },
        expect.any(Object),
      );
      expect(ok.statusCode).toBe(201);
      expect(ok.body).toEqual({ pid: 7 });
    });

    test('DELETE validates the pid then enqueues killSpawn', async () => {
      const { app, deps } = setup({ sendCommand: jest.fn().mockResolvedValue({ status: 200, body: { ok: true } }) });

      const bad = createRes();
      await invoke(app.find('delete', '/terminal/:mac/spawn/:pid'), { authUser: 'alice', params: { mac: MAC, pid: 'abc' } }, bad);
      expect(bad.statusCode).toBe(400);
      expect(deps.sendCommand).not.toHaveBeenCalled();

      const ok = createRes();
      await invoke(app.find('delete', '/terminal/:mac/spawn/:pid'), { authUser: 'alice', params: { mac: MAC, pid: '7' } }, ok);
      expect(deps.sendCommand).toHaveBeenCalledWith({ type: 'killSpawn', mac: MAC, pid: 7 }, expect.any(Object));
      expect(ok.statusCode).toBe(200);
    });
  });
});
