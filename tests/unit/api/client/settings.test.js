'use strict';

const registerSettingsRoutes = require('../../../../api/client/routes/settings');
const { DEFAULT_RING_SIZE, MAX_RING_SIZE } = require('../../../../api/lib/fuzzRing');

function createApp() {
  const routes = [];
  const record = (method) => (path, ...chain) => routes.push({ method, path, chain });
  return {
    routes,
    get: record('get'),
    put: record('put'),
    find(method, path) { return routes.find((r) => r.method === method && r.path === path); },
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

function setup(deps = {}) {
  const app = createApp();
  registerSettingsRoutes(app, {
    parseBody: (req, res, next) => next(),
    ...deps,
  });
  return app;
}

describe('client settings routes', () => {
  test('GET returns the stored ring size alongside the default and max', async () => {
    const app = setup({ getFuzzRingSize: jest.fn().mockResolvedValue(25) });
    const res = createRes();
    await invoke(app.find('get', '/settings/fuzz-ring-size'), { authUser: 'alice' }, res);

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ ringSize: 25, default: DEFAULT_RING_SIZE, max: MAX_RING_SIZE });
  });

  test('GET surfaces a settings-store failure as 500', async () => {
    const app = setup({ getFuzzRingSize: jest.fn().mockRejectedValue(new Error('db down')) });
    const res = createRes();
    await invoke(app.find('get', '/settings/fuzz-ring-size'), { authUser: 'alice' }, res);

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ error: 'internal error' });
  });

  test('PUT stores the new size and echoes it back', async () => {
    const setFuzzRingSize = jest.fn().mockResolvedValue(40);
    const app = setup({ setFuzzRingSize });
    const res = createRes();
    await invoke(
      app.find('put', '/settings/fuzz-ring-size'),
      { authUser: 'alice', body: { ringSize: 40 } },
      res,
    );

    expect(setFuzzRingSize).toHaveBeenCalledWith(40);
    expect(res.statusCode).toBe(200);
    expect(res.body).toMatchObject({ ringSize: 40 });
  });

  test('PUT rejects an out-of-range size as a 400, not a 500', async () => {
    // the store is the validator; the route only has to classify its RangeError
    const setFuzzRingSize = jest.fn()
      .mockRejectedValue(new RangeError('ring size must be an integer between 1 and 1000'));
    const app = setup({ setFuzzRingSize });
    const res = createRes();
    await invoke(
      app.find('put', '/settings/fuzz-ring-size'),
      { authUser: 'alice', body: { ringSize: 0 } },
      res,
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'ring size must be an integer between 1 and 1000' });
  });

  test('PUT with no body reaches the store as undefined and 400s', async () => {
    const setFuzzRingSize = jest.fn().mockRejectedValue(new RangeError('bad'));
    const app = setup({ setFuzzRingSize });
    const res = createRes();
    await invoke(app.find('put', '/settings/fuzz-ring-size'), { authUser: 'alice' }, res);

    expect(setFuzzRingSize).toHaveBeenCalledWith(undefined);
    expect(res.statusCode).toBe(400);
  });
});
