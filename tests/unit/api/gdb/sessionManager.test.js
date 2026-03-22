'use strict';

const { createSessionManager } = require('../../../../api/gdb/sessionManager');

const KEY  = 'aabbccddeeff00112233445566778899';
const KEY2 = '00000000000000000000000000000001';

function mockWs(open = true) {
  return {
    OPEN: 1,
    readyState: open ? 1 : 0,
    send: jest.fn(),
    close: jest.fn(),
  };
}

describe('createSessionManager', () => {
  test('getOrCreate creates a new session with null sides', () => {
    const sm = createSessionManager();
    expect(sm.getOrCreate(KEY)).toEqual({ in: null, out: null });
  });

  test('getOrCreate returns the same object on second call', () => {
    const sm = createSessionManager();
    const s1 = sm.getOrCreate(KEY);
    const s2 = sm.getOrCreate(KEY);
    expect(s1).toBe(s2);
  });

  test('sessions map is accessible and reflects getOrCreate', () => {
    const sm = createSessionManager();
    sm.getOrCreate(KEY);
    expect(sm.sessions.has(KEY)).toBe(true);
  });

  test('relay sends binary data to an open WebSocket', () => {
    const sm = createSessionManager();
    const ws = mockWs(true);
    sm.relay(ws, Buffer.from([1, 2, 3]));
    expect(ws.send).toHaveBeenCalledWith(Buffer.from([1, 2, 3]));
  });

  test('relay does not send to a closed WebSocket', () => {
    const sm = createSessionManager();
    const ws = mockWs(false);
    sm.relay(ws, Buffer.from([1]));
    expect(ws.send).not.toHaveBeenCalled();
  });

  test('relay does not throw when dst is null', () => {
    const sm = createSessionManager();
    expect(() => sm.relay(null, Buffer.from([1]))).not.toThrow();
  });

  test('relay does not throw when dst is undefined', () => {
    const sm = createSessionManager();
    expect(() => sm.relay(undefined, Buffer.from([1]))).not.toThrow();
  });

  test('purge closes in and out WebSockets and removes the session', () => {
    const sm  = createSessionManager();
    const wsIn  = mockWs(true);
    const wsOut = mockWs(true);
    const s = sm.getOrCreate(KEY);
    s.in  = wsIn;
    s.out = wsOut;

    sm.purge(KEY);

    expect(wsIn.close).toHaveBeenCalled();
    expect(wsOut.close).toHaveBeenCalled();
    expect(sm.sessions.has(KEY)).toBe(false);
  });

  test('purge with null sides does not throw', () => {
    const sm = createSessionManager();
    sm.getOrCreate(KEY); // { in: null, out: null }
    expect(() => sm.purge(KEY)).not.toThrow();
    expect(sm.sessions.has(KEY)).toBe(false);
  });

  test('purge with unknown key does not throw', () => {
    const sm = createSessionManager();
    expect(() => sm.purge('nonexistent')).not.toThrow();
  });

  test('purge only removes the targeted session', () => {
    const sm = createSessionManager();
    sm.getOrCreate(KEY);
    sm.getOrCreate(KEY2);

    sm.purge(KEY);

    expect(sm.sessions.has(KEY)).toBe(false);
    expect(sm.sessions.has(KEY2)).toBe(true);
  });

  test('keys returns all present keys', () => {
    const sm = createSessionManager();
    sm.getOrCreate(KEY);
    sm.getOrCreate(KEY2);

    const all = [...sm.keys()];
    expect(all).toContain(KEY);
    expect(all).toContain(KEY2);
  });

  test('independent managers do not share state', () => {
    const sm1 = createSessionManager();
    const sm2 = createSessionManager();
    sm1.getOrCreate(KEY);

    expect(sm2.sessions.has(KEY)).toBe(false);
  });
});
