'use strict';

const crypto = require('crypto');

function hashKey(k) {
  return crypto.createHash('sha256').update(k, 'utf8').digest('hex');
}

function loadAuth() {
  jest.resetModules();
  return require('../../../api/auth');
}

function makeRes() {
  return {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  };
}

describe('api auth', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('checkBearer resolves the matched username and reads keys per call', async () => {
    const auth = loadAuth();
    const loadKeys = jest.fn().mockResolvedValue([
      { keyHash: hashKey('alpha'), username: 'alice' },
      { keyHash: hashKey('beta'), username: 'bob' },
    ]);
    await auth.init(false, loadKeys);

    await expect(auth.checkBearer('Bearer alpha')).resolves.toBe('alice');
    await expect(auth.checkBearer('Bearer beta')).resolves.toBe('bob');
    await expect(auth.checkBearer('Bearer gamma')).resolves.toBe(false);
    // Keys are read from the loader (the DB) on every check, not cached.
    expect(loadKeys).toHaveBeenCalledTimes(3);
  });

  test('init always succeeds; key state is dynamic', async () => {
    const auth = loadAuth();
    expect(await auth.init(true, async () => [])).toBe(true);
    expect(await auth.init(false, async () => [])).toBe(true);
  });

  test('enforcement is dynamic: open with no keys, enforced once a key exists', async () => {
    const auth = loadAuth();
    let keys = [];
    await auth.init(false, async () => keys);

    // No keys configured -> open.
    await expect(auth.checkBearer(undefined)).resolves.toBe(true);
    await expect(auth.checkBearer('Bearer anything')).resolves.toBe(true);

    // A key appears in the DB -> now enforced; only a valid token passes.
    keys = [{ keyHash: hashKey('secret'), username: 'alice' }];
    await expect(auth.checkBearer(undefined)).resolves.toBe(false);
    await expect(auth.checkBearer('Bearer wrong')).resolves.toBe(false);
    await expect(auth.checkBearer('Bearer secret')).resolves.toBe('alice');
  });

  test('enforced=true rejects even when no keys exist', async () => {
    const auth = loadAuth();
    await auth.init(true, async () => []);
    await expect(auth.checkBearer('Bearer anything')).resolves.toBe(false);
    await expect(auth.checkBearer(undefined)).resolves.toBe(false);
  });

  test('resolveBearer accepts an explicit loader + enforced flag (gdb scopes)', async () => {
    const auth = loadAuth();
    const agentKeys = [{ keyHash: hashKey('agenttok'), username: 'alice' }];

    // No init() — the loader is passed explicitly (one per gdb direction).
    await expect(auth.resolveBearer('Bearer agenttok', async () => agentKeys, false)).resolves.toBe('alice');
    await expect(auth.resolveBearer('Bearer nope', async () => agentKeys, false)).resolves.toBe(false);
    // Open when that scope has no keys.
    await expect(auth.resolveBearer('Bearer anything', async () => [], false)).resolves.toBe(true);
  });

  test('matchBearer matches against an explicit key set, statelessly', () => {
    const auth = loadAuth();
    const keys = [
      { keyHash: hashKey('agenttok'), username: 'alice' },
      { keyHash: hashKey('clienttok'), username: 'bob' },
    ];

    expect(auth.matchBearer('Bearer agenttok', keys)).toBe('alice');
    expect(auth.matchBearer('Bearer clienttok', keys)).toBe('bob');
    expect(auth.matchBearer('Bearer nope', keys)).toBeNull();
    expect(auth.matchBearer(undefined, keys)).toBeNull();
    expect(auth.matchBearer('Basic agenttok', keys)).toBeNull();
    expect(auth.matchBearer('Bearer agenttok', [])).toBeNull();
  });

  test('middleware returns 401 json when bearer token is invalid', async () => {
    const auth = loadAuth();
    await auth.init(false, async () => [{ keyHash: hashKey('secret'), username: 'alice' }]);

    const req = { headers: {} };
    const res = makeRes();
    const next = jest.fn();

    await auth.middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
  });

  test('middleware calls next and attaches identity when the token is valid', async () => {
    const auth = loadAuth();
    await auth.init(false, async () => [{ keyHash: hashKey('secret'), username: 'alice' }]);

    const req = { headers: { authorization: 'Bearer secret' } };
    const res = makeRes();
    const next = jest.fn();

    await auth.middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(req.authKeyHash).toBe(hashKey('secret'));
    expect(req.authUser).toBe('alice');
  });

  test('middleware is open (no user) when no keys are configured', async () => {
    const auth = loadAuth();
    await auth.init(false, async () => []);

    const req = { headers: { authorization: 'Bearer anytoken' } };
    const res = makeRes();
    const next = jest.fn();

    await auth.middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.authKeyHash).toBe(hashKey('anytoken'));
    expect(req.authUser).toBeUndefined();
  });

  test('middleware fails closed (401) when the key loader throws', async () => {
    const auth = loadAuth();
    await auth.init(false, async () => { throw new Error('db down'); });

    const req = { headers: { authorization: 'Bearer secret' } };
    const res = makeRes();
    const next = jest.fn();

    await auth.middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });
});
