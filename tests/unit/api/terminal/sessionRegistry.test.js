'use strict';

const { createSessionRegistry } = require('../../../../api/terminal/sessionRegistry');

describe('session registry', () => {
  test('adds, lists, and removes sessions', () => {
    const timers = [];
    const registry = createSessionRegistry({
      heartbeatIntervalMs: 1000,
      setIntervalImpl: (fn) => {
        timers.push(fn);
        return fn;
      },
      clearIntervalImpl: jest.fn(),
    });

    const ws = { OPEN: 1, readyState: 1, send: jest.fn() };
    const entry = registry.addSession('aa:bb', ws, { alias: 'router', connectionId: 9, group: '192.168.1.1' });

    expect(entry.alias).toBe('router');
    expect(entry.group).toBe('192.168.1.1');
    expect(registry.listMacs()).toEqual(['aa:bb']);
    timers[0]();
    expect(ws.send).toHaveBeenCalledWith(JSON.stringify({ _type: 'heartbeat' }));

    registry.removeSession('aa:bb');
    expect(registry.size).toBe(0);
  });
});
