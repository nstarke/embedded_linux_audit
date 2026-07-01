'use strict';

const registerGdbRoutes = require('../../../../api/client/routes/gdb');

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

async function invoke(route, req, res) {
  const chain = route.chain.filter((fn) => typeof fn === 'function');
  for (const fn of chain) {
    let advanced = false;
    // eslint-disable-next-line no-await-in-loop
    await fn(req, res, () => { advanced = true; });
    if (!advanced) return;
  }
}

const MAC = 'aa:bb:cc:dd:ee:ff';

function setup(overrides = {}) {
  const app = createApp();
  const deps = {
    sendCommand: jest.fn().mockResolvedValue({ status: 200, body: { sessions: [] } }),
    listUserDeviceMacs: jest.fn().mockResolvedValue([MAC]),
    ...overrides,
  };
  registerGdbRoutes(app, deps);
  return { app, deps };
}

describe('client GDB routes', () => {
  test('lists only sessions on the caller\'s associated devices', async () => {
    const { app, deps } = setup({
      sendCommand: jest.fn().mockResolvedValue({
        status: 200,
        body: {
          sessions: [
            { hexkey: 'k1', mac: 'aa:bb:cc:dd:ee:ff', operatorConnected: false },
            { hexkey: 'k2', mac: 'aa:bb:cc:dd:ee:ff', operatorConnected: true },
            { hexkey: 'k3', mac: '11:22:33:44:55:66', operatorConnected: false }, // not associated
          ],
        },
      }),
    });
    const res = createRes();
    await invoke(app.find('get', '/gdb/sessions'), { authUser: 'alice' }, res);

    expect(deps.sendCommand).toHaveBeenCalledWith({ type: 'sessions' }, { waitMs: 30000 });
    expect(res.statusCode).toBe(200);
    // Both sessions on the associated MAC are returned (multiple per MAC), the
    // unassociated one is filtered out.
    expect(res.body.sessions.map((s) => s.hexkey)).toEqual(['k1', 'k2']);
    expect(res.body.sessions.find((s) => s.hexkey === 'k2').operatorConnected).toBe(true);
  });

  test('matches associated devices regardless of MAC separator', async () => {
    const { app } = setup({
      // User's device is stored with dashes; the session reports colons.
      listUserDeviceMacs: jest.fn().mockResolvedValue(['aa-bb-cc-dd-ee-ff']),
      sendCommand: jest.fn().mockResolvedValue({
        status: 200,
        body: { sessions: [{ hexkey: 'k1', mac: 'AA:BB:CC:DD:EE:FF', operatorConnected: false }] },
      }),
    });
    const res = createRes();
    await invoke(app.find('get', '/gdb/sessions'), { authUser: 'alice' }, res);
    expect(res.body.sessions.map((s) => s.hexkey)).toEqual(['k1']);
  });

  test('returns 504 when the GDB API is unavailable', async () => {
    const { app } = setup({ sendCommand: jest.fn().mockRejectedValue(new Error('down')) });
    const res = createRes();
    await invoke(app.find('get', '/gdb/sessions'), { authUser: 'alice' }, res);
    expect(res.statusCode).toBe(504);
  });

  test('relays a non-200 worker status', async () => {
    const { app } = setup({
      sendCommand: jest.fn().mockResolvedValue({ status: 400, body: { error: 'bad' } }),
    });
    const res = createRes();
    await invoke(app.find('get', '/gdb/sessions'), { authUser: 'alice' }, res);
    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'bad' });
  });

  test('returns 500 when the device lookup fails', async () => {
    const { app } = setup({ listUserDeviceMacs: jest.fn().mockRejectedValue(new Error('db')) });
    const res = createRes();
    await invoke(app.find('get', '/gdb/sessions'), { authUser: 'alice' }, res);
    expect(res.statusCode).toBe(500);
  });
});
