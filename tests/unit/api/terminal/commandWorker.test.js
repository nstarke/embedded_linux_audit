'use strict';

const { processCommand, buildSessionList } = require('../../../../api/terminal/commandWorker');

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

    test('200 with output on success; default mode wraps as a shell command', async () => {
      const sessionRegistry = registry([['aa:bb', { ws: {} }]]);
      const runExecImpl = jest.fn().mockResolvedValue({ output: 'uid=0', durationMs: 7 });
      const res = await run({ type: 'exec', mac: 'aa:bb', command: 'id', timeoutMs: 1000 }, { sessionRegistry, runExecImpl });
      expect(runExecImpl).toHaveBeenCalledWith({ entry: { ws: {} }, mac: 'aa:bb', command: 'id', timeoutMs: 1000, wrapShell: true });
      expect(res).toEqual({ status: 200, body: { ok: true, output: 'uid=0', durationMs: 7 } });
    });

    test("mode 'ela' sends the command verbatim (wrapShell false)", async () => {
      const sessionRegistry = registry([['aa:bb', { ws: {} }]]);
      const runExecImpl = jest.fn().mockResolvedValue({ output: 'ok', durationMs: 1 });
      await run({ type: 'exec', mode: 'ela', mac: 'aa:bb', command: 'linux dmesg' }, { sessionRegistry, runExecImpl });
      expect(runExecImpl).toHaveBeenCalledWith(expect.objectContaining({ command: 'linux dmesg', wrapShell: false }));
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

    test("mode 'ela' runs the raw command (no PID) and returns its output", async () => {
      const sessionRegistry = registry([['aa:bb', { ws: {} }]]);
      const runExecImpl = jest.fn().mockResolvedValue({ output: 'wss://h/gdb/out/abc', durationMs: 3 });
      const runSpawnImpl = jest.fn();
      const res = await run(
        { type: 'spawn', mode: 'ela', mac: 'aa:bb', command: 'linux gdbserver tunnel 42 wss://h' },
        { sessionRegistry, runExecImpl, runSpawnImpl },
      );
      // ELA spawn does not shell-background, so runSpawn is not used.
      expect(runSpawnImpl).not.toHaveBeenCalled();
      expect(runExecImpl).toHaveBeenCalledWith(expect.objectContaining({ command: 'linux gdbserver tunnel 42 wss://h', wrapShell: false }));
      expect(res).toEqual({ status: 201, body: { ok: true, output: 'wss://h/gdb/out/abc', durationMs: 3 } });
    });
  });

  describe('setMeta', () => {
    test('persists alias and group and mirrors them onto a connected entry', async () => {
      const entry = { ws: {}, alias: 'old', group: 'oldg' };
      const sessionRegistry = registry([['aa:bb', entry]]);
      const setDeviceAliasImpl = jest.fn().mockResolvedValue('router');
      const setDeviceGroupImpl = jest.fn().mockResolvedValue('field');

      const res = await run(
        { type: 'setMeta', mac: 'aa:bb', alias: 'router', group: 'field' },
        { sessionRegistry, setDeviceAliasImpl, setDeviceGroupImpl },
      );

      expect(setDeviceAliasImpl).toHaveBeenCalledWith('aa:bb', 'router');
      expect(setDeviceGroupImpl).toHaveBeenCalledWith('aa:bb', 'field');
      expect(res).toEqual({ status: 200, body: { mac: 'aa:bb', alias: 'router', group: 'field' } });
      // Live entry updated so the sessions listing reflects it immediately.
      expect(entry.alias).toBe('router');
      expect(entry.group).toBe('field');
    });

    test('only updates the field that was provided (undefined = leave unchanged)', async () => {
      const entry = { ws: {}, alias: 'keep', group: 'keepg' };
      const sessionRegistry = registry([['aa:bb', entry]]);
      const setDeviceAliasImpl = jest.fn().mockResolvedValue('newalias');
      const setDeviceGroupImpl = jest.fn();

      const res = await run(
        { type: 'setMeta', mac: 'aa:bb', alias: 'newalias' },
        { sessionRegistry, setDeviceAliasImpl, setDeviceGroupImpl },
      );

      expect(setDeviceGroupImpl).not.toHaveBeenCalled();
      expect(res.body).toEqual({ mac: 'aa:bb', alias: 'newalias', group: 'keepg' });
      expect(entry.group).toBe('keepg');
    });

    test('works without a live session (persists to the DB only)', async () => {
      const sessionRegistry = registry();
      const setDeviceGroupImpl = jest.fn().mockResolvedValue('g');
      const res = await run(
        { type: 'setMeta', mac: 'aa:bb', group: 'g' },
        { sessionRegistry, setDeviceGroupImpl, setDeviceAliasImpl: jest.fn() },
      );
      expect(setDeviceGroupImpl).toHaveBeenCalledWith('aa:bb', 'g');
      expect(res).toEqual({ status: 200, body: { mac: 'aa:bb', alias: null, group: 'g' } });
    });

    test('a null value clears the field', async () => {
      const sessionRegistry = registry([['aa:bb', { ws: {}, alias: 'x' }]]);
      const setDeviceAliasImpl = jest.fn().mockResolvedValue(null);
      const res = await run(
        { type: 'setMeta', mac: 'aa:bb', alias: null },
        { sessionRegistry, setDeviceAliasImpl, setDeviceGroupImpl: jest.fn() },
      );
      expect(setDeviceAliasImpl).toHaveBeenCalledWith('aa:bb', null);
      expect(res.body.alias).toBeNull();
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

  describe('per-device serialization', () => {
    // A controllable async op: returns a promise plus its resolver so a test can
    // hold a command "in flight" and observe what runs while it is pending.
    function deferred() {
      let resolve;
      const promise = new Promise((r) => { resolve = r; });
      return { promise, resolve };
    }
    // Fully drain the microtask queue (the per-device lock chains via .then).
    const tick = () => new Promise((r) => setImmediate(r));

    test('two exec commands on the SAME mac do not overlap', async () => {
      const sessionRegistry = registry([['aa:bb', { ws: {} }]]);
      const first = deferred();
      const second = deferred();
      let started = 0;
      const runExecImpl = jest.fn(() => {
        const which = started === 0 ? first : second;
        started += 1;
        return which.promise.then(() => ({ output: 'x', durationMs: 1 }));
      });

      const p1 = run({ type: 'exec', mac: 'aa:bb', command: 'a' }, { sessionRegistry, runExecImpl });
      const p2 = run({ type: 'exec', mac: 'aa:bb', command: 'b' }, { sessionRegistry, runExecImpl });
      await tick();

      // The second command must NOT have started while the first is in flight.
      expect(runExecImpl).toHaveBeenCalledTimes(1);
      first.resolve();
      await p1;
      await tick();
      expect(runExecImpl).toHaveBeenCalledTimes(2);
      second.resolve();
      await p2;
    });

    test('exec commands on DIFFERENT macs run concurrently', async () => {
      const sessionRegistry = registry([['aa:bb', { ws: {} }], ['cc:dd', { ws: {} }]]);
      const gate = deferred();
      const runExecImpl = jest.fn(() => gate.promise.then(() => ({ output: 'x', durationMs: 1 })));

      const p1 = run({ type: 'exec', mac: 'aa:bb', command: 'a' }, { sessionRegistry, runExecImpl });
      const p2 = run({ type: 'exec', mac: 'cc:dd', command: 'b' }, { sessionRegistry, runExecImpl });
      await tick();

      // Both devices' commands are in flight at once — no cross-device blocking.
      expect(runExecImpl).toHaveBeenCalledTimes(2);
      gate.resolve();
      await Promise.all([p1, p2]);
    });

    test('a sessions listing is never blocked by an in-flight exec', async () => {
      const sessionRegistry = registry([['aa:bb', { ws: {}, alias: 'router' }]]);
      const gate = deferred();
      const runExecImpl = jest.fn(() => gate.promise.then(() => ({ output: 'x', durationMs: 1 })));

      const execP = run({ type: 'exec', mac: 'aa:bb', command: 'slow' }, { sessionRegistry, runExecImpl });
      const sessionsRes = await run({ type: 'sessions' }, { sessionRegistry });

      // sessions resolves immediately even though the exec is still pending.
      expect(sessionsRes.status).toBe(200);
      expect(sessionsRes.body.sessions[0].alias).toBe('router');
      gate.resolve();
      await execP;
    });
  });
});

describe('buildSessionList', () => {
  test('projects the operator-visible fields, defaulting missing ones to null', () => {
    const sessionRegistry = registry([
      ['aa:bb', { alias: 'router', group: 'g', remoteAddress: '10.0.0.1', connectedAt: 't0', lastHeartbeat: 't1' }],
      ['cc:dd', {}],
    ]);
    expect(buildSessionList(sessionRegistry)).toEqual([
      { mac: 'aa:bb', alias: 'router', group: 'g', remoteAddress: '10.0.0.1', connectedAt: 't0', lastHeartbeat: 't1' },
      { mac: 'cc:dd', alias: null, group: null, remoteAddress: null, connectedAt: null, lastHeartbeat: null },
    ]);
  });
});
