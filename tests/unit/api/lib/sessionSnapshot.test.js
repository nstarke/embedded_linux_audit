'use strict';

// Load sessionSnapshot with ioredis replaced by an in-memory stand-in, so these
// tests never touch a real Redis. Mirrors the jest.doMock(..., { virtual: true })
// pattern used for bullmq in queue.test.js (the real package lives under
// api/node_modules and is not resolvable from the test root).
function loadSnapshot() {
  jest.resetModules();
  const store = new Map();
  let lastSet = null;
  const client = {
    on: jest.fn(),
    async set(key, value, mode, ttl) {
      lastSet = { key, value, mode, ttl };
      store.set(key, value);
      return 'OK';
    },
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async quit() { return 'OK'; },
    disconnect: jest.fn(),
  };
  const Redis = jest.fn(() => client);
  jest.doMock('ioredis', () => Redis, { virtual: true });
  const mod = require('../../../../api/lib/sessionSnapshot');
  return { mod, store, getLastSet: () => lastSet };
}

describe('sessionSnapshot', () => {
  afterEach(() => {
    jest.resetModules();
  });

  test('publish writes the session list under the snapshot key with a TTL', async () => {
    const { mod, getLastSet } = loadSnapshot();
    const sessions = [{ mac: 'aa:bb', alias: 'router' }];
    await mod.publishSessionSnapshot(sessions, { now: () => 1000 });

    const lastSet = getLastSet();
    expect(lastSet.key).toBe(mod.SESSION_SNAPSHOT_KEY);
    expect(lastSet.mode).toBe('EX');
    expect(lastSet.ttl).toBe(mod.SNAPSHOT_TTL_SECONDS);
    expect(JSON.parse(lastSet.value)).toEqual({ sessions, updatedAt: 1000 });
  });

  test('read returns the sessions and computes age from updatedAt', async () => {
    const { mod } = loadSnapshot();
    await mod.publishSessionSnapshot([{ mac: 'aa:bb' }], { now: () => 1000 });
    const snap = await mod.readSessionSnapshot({ now: () => 4000 });
    expect(snap).toEqual({ sessions: [{ mac: 'aa:bb' }], updatedAt: 1000, ageMs: 3000 });
  });

  test('read returns null when there is no snapshot', async () => {
    const { mod } = loadSnapshot();
    expect(await mod.readSessionSnapshot()).toBeNull();
  });

  test('readFresh serves a recent snapshot but returns null once it is stale', async () => {
    const { mod } = loadSnapshot();
    await mod.publishSessionSnapshot([{ mac: 'aa:bb' }], { now: () => 1000 });

    // Well within the staleness window.
    expect(await mod.readFreshSessionSnapshot({ now: () => 2000 })).toEqual([{ mac: 'aa:bb' }]);
    // Far beyond it -> caller should fall back to the queue.
    expect(await mod.readFreshSessionSnapshot({ now: () => 10 ** 9 })).toBeNull();
  });
});
