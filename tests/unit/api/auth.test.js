'use strict';

const crypto = require('crypto');

function hashKey(k) {
  return crypto.createHash('sha256').update(k, 'utf8').digest('hex');
}

function loadAuth() {
  jest.resetModules();
  return require('../../../api/auth');
}

describe('api auth', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('init loads key hashes and checkBearer returns the matched username', async () => {
    const auth = loadAuth();
    const loadKeys = jest.fn().mockResolvedValue([
      { keyHash: hashKey('alpha'), username: 'alice' },
      { keyHash: hashKey('beta'), username: 'bob' },
    ]);

    expect(await auth.init(true, loadKeys)).toBe(true);
    expect(loadKeys).toHaveBeenCalledTimes(1);
    expect(auth.checkBearer('Bearer alpha')).toBe('alice');
    expect(auth.checkBearer('Bearer beta')).toBe('bob');
    expect(auth.checkBearer('Bearer gamma')).toBe(false);
  });

  test('init returns false when enforcement is enabled and no keys exist', async () => {
    const auth = loadAuth();

    expect(await auth.init(true, async () => [])).toBe(false);
  });

  test('matchBearer matches against an explicit key set, independent of enforcement', () => {
    const auth = loadAuth();
    const keys = [
      { keyHash: hashKey('agenttok'), username: 'alice' },
      { keyHash: hashKey('clienttok'), username: 'bob' },
    ];

    // No init() call — matchBearer is stateless.
    expect(auth.matchBearer('Bearer agenttok', keys)).toBe('alice');
    expect(auth.matchBearer('Bearer clienttok', keys)).toBe('bob');
    expect(auth.matchBearer('Bearer nope', keys)).toBeNull();
    expect(auth.matchBearer(undefined, keys)).toBeNull();
    expect(auth.matchBearer('Basic agenttok', keys)).toBeNull();
    expect(auth.matchBearer('Bearer agenttok', [])).toBeNull();
  });

  test('auth is disabled when enforcement is off — checkBearer returns true for any header', async () => {
    const auth = loadAuth();

    expect(await auth.init(false, async () => [])).toBe(true);
    expect(auth.checkBearer(undefined)).toBe(true);
    expect(auth.checkBearer('not even bearer')).toBe(true);
    expect(auth.checkBearer('Bearer anything')).toBe(true);
  });

  test('checkBearer rejects missing and malformed authorization headers in enforced mode', async () => {
    const auth = loadAuth();
    await auth.init(true, async () => [{ keyHash: hashKey('secret'), username: 'alice' }]);

    expect(auth.checkBearer(undefined)).toBe(false);
    expect(auth.checkBearer('Basic secret')).toBe(false);
    expect(auth.checkBearer('Bearer wrong')).toBe(false);
    expect(auth.checkBearer('Bearer secret')).toBe('alice');
  });

  test('middleware returns 401 json when bearer token is invalid', async () => {
    const auth = loadAuth();
    await auth.init(true, async () => [{ keyHash: hashKey('secret'), username: 'alice' }]);

    const req = { headers: {} };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    auth.middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
  });

  test('middleware calls next when bearer token is valid', async () => {
    const auth = loadAuth();
    await auth.init(true, async () => [{ keyHash: hashKey('secret'), username: 'alice' }]);

    const req = { headers: { authorization: 'Bearer secret' } };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    auth.middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(res.json).not.toHaveBeenCalled();
  });

  test('middleware attaches the token hash and username for per-user asset serving', async () => {
    const auth = loadAuth();
    await auth.init(true, async () => [{ keyHash: hashKey('secret'), username: 'alice' }]);

    const req = { headers: { authorization: 'Bearer secret' } };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    auth.middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.authKeyHash).toBe(hashKey('secret'));
    expect(req.authUser).toBe('alice');
  });

  test('middleware attaches the token hash even when enforcement is off', async () => {
    const auth = loadAuth();
    await auth.init(false, async () => []);

    const req = { headers: { authorization: 'Bearer anytoken' } };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    auth.middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.authKeyHash).toBe(hashKey('anytoken'));
    // No specific user matched (enforcement off), so authUser stays unset.
    expect(req.authUser).toBeUndefined();
  });
});
