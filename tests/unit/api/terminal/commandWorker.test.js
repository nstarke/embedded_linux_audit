'use strict';

const { processCommand } = require('../../../../api/terminal/commandWorker');

function registry(entries = []) {
  const map = new Map(entries);
  return {
    entries: () => [...map.entries()],
    getSession: (mac) => map.get(mac),
    _map: map,
  };
}

function run(data, opts = {}) {
  return processCommand({ job: { data }, ...opts });
}

describe('processCommand', () => {
  test('sessions returns the live sessions', async () => {
    const sessionRegistry = registry([
      ['aa:bb', { alias: 'router', group: 'g', remoteAddress: '10.0.0.1', connectedAt: 't0', lastHeartbeat: 't1' }],
    ]);
    const res = await run({ type: 'sessions' }, { sessionRegistry });
    expect(res).toEqual({
      status: 200,
      body: { sessions: [{ mac: 'aa:bb', alias: 'router', group: 'g', remoteAddress: '10.0.0.1', connectedAt: 't0', lastHeartbeat: 't1' }] },
    });
  });

  test('unknown command type is a 400', async () => {
    const res = await run({ type: 'bogus' }, { sessionRegistry: registry() });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/unknown command type/);
  });

  describe('exec', () => {
    test('404 when there is no session for the mac', async () => {
      const res = await run({ type: 'exec', mac: 'aa:bb', command: 'id' }, { sessionRegistry: registry() });
      expect(res).toEqual({ status: 404, body: { error: 'no active session for mac' } });
    });

    test('200 with output on success', async () => {
      const sessionRegistry = registry([['aa:bb', { ws: {} }]]);
      const runExecImpl = jest.fn().mockResolvedValue({ output: 'uid=0', durationMs: 7 });
      const res = await run({ type: 'exec', mac: 'aa:bb', command: 'id', timeoutMs: 1000 }, { sessionRegistry, runExecImpl });
      expect(runExecImpl).toHaveBeenCalledWith({ entry: { ws: {} }, mac: 'aa:bb', command: 'id', timeoutMs: 1000 });
      expect(res).toEqual({ status: 200, body: { ok: true, output: 'uid=0', durationMs: 7 } });
    });

    test('504 on timeout, 404 on NOT_CONNECTED, 500 otherwise', async () => {
      const sessionRegistry = registry([['aa:bb', { ws: {} }]]);
      const timeout = Object.assign(new Error('t'), { code: 'TIMEOUT', output: 'partial', durationMs: 3 });
      const disc = Object.assign(new Error('d'), { code: 'NOT_CONNECTED' });

      const r1 = await run({ type: 'exec', mac: 'aa:bb', command: 'x' }, { sessionRegistry, runExecImpl: jest.fn().mockRejectedValue(timeout) });
      expect(r1).toEqual({ status: 504, body: { ok: false, error: 'exec timed out', output: 'partial', durationMs: 3 } });

      const r2 = await run({ type: 'exec', mac: 'aa:bb', command: 'x' }, { sessionRegistry, runExecImpl: jest.fn().mockRejectedValue(disc) });
      expect(r2).toEqual({ status: 404, body: { error: 'no active session for mac' } });

      const r3 = await run({ type: 'exec', mac: 'aa:bb', command: 'x' }, { sessionRegistry, runExecImpl: jest.fn().mockRejectedValue(new Error('boom')) });
      expect(r3).toEqual({ status: 500, body: { error: 'exec failed' } });
    });
  });

  describe('spawn', () => {
    test('201 with pid/port and records the spawn on the entry', async () => {
      const entry = { ws: {} };
      const sessionRegistry = registry([['aa:bb', entry]]);
      const runSpawnImpl = jest.fn().mockResolvedValue({ pid: 4242, port: 5555 });
      const res = await run(
        { type: 'spawn', mac: 'aa:bb', command: 'gdbserver', args: ['--x'], port: 5555 },
        { sessionRegistry, runSpawnImpl, now: () => 'START' },
      );
      expect(res).toEqual({ status: 201, body: { pid: 4242, port: 5555 } });
      expect(entry.spawns.get(4242)).toEqual({ pid: 4242, command: 'gdbserver', args: ['--x'], port: 5555, startedAt: 'START' });
    });

    test('404 without a session; 504 on timeout', async () => {
      expect(await run({ type: 'spawn', mac: 'aa:bb', command: 'x' }, { sessionRegistry: registry() }))
        .toEqual({ status: 404, body: { error: 'no active session for mac' } });

      const sessionRegistry = registry([['aa:bb', { ws: {} }]]);
      const timeout = Object.assign(new Error('t'), { code: 'TIMEOUT' });
      expect(await run({ type: 'spawn', mac: 'aa:bb', command: 'x' }, { sessionRegistry, runSpawnImpl: jest.fn().mockRejectedValue(timeout) }))
        .toEqual({ status: 504, body: { error: 'spawn timed out' } });
    });
  });

  describe('listSpawns / killSpawn', () => {
    test('listSpawns serializes the tracked spawns', async () => {
      const entry = { ws: {}, spawns: new Map([[7, { pid: 7, command: 'c', args: [], startedAt: 't', port: 9 }]]) };
      const sessionRegistry = registry([['aa:bb', entry]]);
      const res = await run({ type: 'listSpawns', mac: 'aa:bb' }, { sessionRegistry });
      expect(res).toEqual({ status: 200, body: { spawns: [{ pid: 7, command: 'c', args: [], startedAt: 't', port: 9 }] } });
    });

    test('killSpawn 404s for an unknown pid, kills a known one', async () => {
      const entry = { ws: {}, spawns: new Map([[7, { pid: 7 }]]) };
      const sessionRegistry = registry([['aa:bb', entry]]);

      const miss = await run({ type: 'killSpawn', mac: 'aa:bb', pid: 99 }, { sessionRegistry, runExecImpl: jest.fn() });
      expect(miss).toEqual({ status: 404, body: { error: 'no such spawn' } });

      const runExecImpl = jest.fn().mockResolvedValue({ output: '', durationMs: 1 });
      const hit = await run({ type: 'killSpawn', mac: 'aa:bb', pid: 7 }, { sessionRegistry, runExecImpl });
      expect(runExecImpl).toHaveBeenCalledWith({ entry, mac: 'aa:bb', command: 'kill 7' });
      expect(hit).toEqual({ status: 200, body: { ok: true } });
      expect(entry.spawns.has(7)).toBe(false);
    });
  });
});
