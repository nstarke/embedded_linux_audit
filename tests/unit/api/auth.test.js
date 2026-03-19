'use strict';

function loadAuthWithFileContent(readImpl) {
  jest.resetModules();

  const readFileSync = jest.fn(readImpl);
  jest.doMock('fs', () => ({ readFileSync }));

  const auth = require('../../../api/auth');
  return { auth, readFileSync };
}

describe('api auth', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
    jest.unmock('fs');
  });

  test('init loads trimmed keys and accepts matching bearer tokens in enforced mode', () => {
    const { auth, readFileSync } = loadAuthWithFileContent(() => '  alpha  \n\nbeta\n');

    expect(auth.init('/tmp/ela.key', true)).toBe(true);
    expect(readFileSync).toHaveBeenCalledWith('/tmp/ela.key', 'utf8');
    expect(auth.checkBearer('Bearer alpha')).toBe(true);
    expect(auth.checkBearer('Bearer beta')).toBe(true);
    expect(auth.checkBearer('Bearer gamma')).toBe(false);
  });

  test('init returns false when enforcement is enabled and key file is missing', () => {
    const missing = Object.assign(new Error('missing'), { code: 'ENOENT' });
    const { auth } = loadAuthWithFileContent(() => {
      throw missing;
    });

    expect(auth.init('/tmp/missing.key', true)).toBe(false);
  });

  test('init returns false when enforcement is enabled and key file is empty', () => {
    const { auth } = loadAuthWithFileContent(() => '\n   \n');

    expect(auth.init('/tmp/empty.key', true)).toBe(false);
  });

  test('auth is disabled when enforcement is off even if key file is missing', () => {
    const missing = Object.assign(new Error('missing'), { code: 'ENOENT' });
    const { auth } = loadAuthWithFileContent(() => {
      throw missing;
    });

    expect(auth.init('/tmp/missing.key', false)).toBe(true);
    expect(auth.checkBearer(undefined)).toBe(true);
    expect(auth.checkBearer('not even bearer')).toBe(true);
  });

  test('checkBearer rejects missing and malformed authorization headers in enforced mode', () => {
    const { auth } = loadAuthWithFileContent(() => 'secret\n');

    expect(auth.init('/tmp/ela.key', true)).toBe(true);
    expect(auth.checkBearer(undefined)).toBe(false);
    expect(auth.checkBearer('Basic secret')).toBe(false);
    expect(auth.checkBearer('Bearer wrong')).toBe(false);
    expect(auth.checkBearer('Bearer secret')).toBe(true);
  });

  test('middleware returns 401 json when bearer token is invalid', () => {
    const { auth } = loadAuthWithFileContent(() => 'secret\n');
    auth.init('/tmp/ela.key', true);

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

  test('middleware calls next when bearer token is valid', () => {
    const { auth } = loadAuthWithFileContent(() => 'secret\n');
    auth.init('/tmp/ela.key', true);

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
});
