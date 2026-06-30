'use strict';

const { runSpawn, buildSpawnLine, shellQuote } = require('../../../../api/terminal/spawnCommand');

function createEntry({ readyState = 1 } = {}) {
  const sent = [];
  const entry = {
    outputListeners: new Set(),
    ws: {
      OPEN: 1,
      readyState,
      send: (data) => sent.push(data),
    },
  };
  // Helper to fan output to the registered listeners, like server.js does.
  entry.emit = (text) => {
    for (const listener of entry.outputListeners) {
      listener(text);
    }
  };
  entry.sent = sent;
  return entry;
}

describe('shellQuote / buildSpawnLine', () => {
  test('quotes the command and args and appends the sentinel echo', () => {
    expect(buildSpawnLine('gdbserver', [':1234', '/bin/ls'])).toBe(
      "'gdbserver' ':1234' '/bin/ls' & echo __ELA_SPAWN__ $!",
    );
  });

  test('escapes embedded single quotes', () => {
    expect(shellQuote("a'b")).toBe("'a'\\''b'");
  });
});

describe('runSpawn', () => {
  const mac = 'aa:bb:cc:dd:ee:ff';

  test('sends a backgrounded command and keeps listening for a port after the pid', async () => {
    const entry = createEntry();
    const timers = [];
    const promise = runSpawn({
      entry,
      mac,
      command: 'sleep',
      args: ['100'],
      setTimeoutImpl: (fn) => {
        timers.push(fn);
        return timers.length;
      },
      clearTimeoutImpl: () => {},
    });

    expect(entry.sent).toEqual([
      'linux execute-command "\'sleep\' \'100\' & echo __ELA_SPAWN__ $!"\n',
    ]);
    expect(entry.outputListeners.size).toBe(1);

    entry.emit('__ELA_SPAWN__ 4242\r\n');
    // The pid is captured but, with no port yet, the listener stays active while
    // the port-wait timer (timers[1]) runs.
    expect(entry.outputListeners.size).toBe(1);

    entry.emit('bound to port 6010\r\n');
    await expect(promise).resolves.toEqual({ pid: 4242, port: 6010 });
    expect(entry.outputListeners.size).toBe(0);
  });

  test('a caller-supplied port resolves immediately after the pid', async () => {
    const entry = createEntry();
    const promise = runSpawn({ entry, mac, command: 'gdbserver', args: [':9999'], port: 9999 });

    entry.emit('__ELA_SPAWN__ 17\r\n');

    await expect(promise).resolves.toEqual({ pid: 17, port: 9999 });
    expect(entry.outputListeners.size).toBe(0);
  });

  test('detects a bound port from the process output', async () => {
    const entry = createEntry();
    const promise = runSpawn({ entry, mac, command: 'gdbserver', args: [':0', 'a.out'] });

    entry.emit('__ELA_SPAWN__ 88\r\n');
    entry.emit('Listening on port 34567\r\n');

    await expect(promise).resolves.toEqual({ pid: 88, port: 34567 });
    expect(entry.outputListeners.size).toBe(0);
  });

  test('resolves with an undefined port when none is reported in the window', async () => {
    const entry = createEntry();
    const timers = [];
    const promise = runSpawn({
      entry,
      mac,
      command: 'sleep',
      args: ['100'],
      setTimeoutImpl: (fn) => {
        timers.push(fn);
        return timers.length;
      },
      clearTimeoutImpl: () => {},
    });

    entry.emit('__ELA_SPAWN__ 555\r\n');
    // timers[0] = pid timeout (cleared after pid), timers[1] = port wait.
    timers[1]();

    await expect(promise).resolves.toEqual({ pid: 555, port: undefined });
    expect(entry.outputListeners.size).toBe(0);
  });

  test('rejects with NOT_CONNECTED when the socket is closed', async () => {
    const entry = createEntry({ readyState: 3 });
    await expect(runSpawn({ entry, mac, command: 'ls' })).rejects.toMatchObject({ code: 'NOT_CONNECTED' });
    expect(entry.sent).toEqual([]);
  });

  test('rejects with TIMEOUT when no pid is reported', async () => {
    const entry = createEntry();
    const timers = [];
    let clock = 0;
    const promise = runSpawn({
      entry,
      mac,
      command: 'sleep 5',
      timeoutMs: 100,
      now: () => clock,
      setTimeoutImpl: (fn) => {
        timers.push(fn);
        return timers.length;
      },
      clearTimeoutImpl: () => {},
    });

    clock = 100;
    timers[0]();

    await expect(promise).rejects.toMatchObject({ code: 'TIMEOUT', durationMs: 100 });
    expect(entry.outputListeners.size).toBe(0);
  });

  test('marks send failures with SEND_FAILED', async () => {
    const entry = createEntry();
    entry.ws.send = () => { throw new Error('socket gone'); };

    await expect(runSpawn({ entry, mac, command: 'ls' })).rejects.toMatchObject({ code: 'SEND_FAILED' });
    expect(entry.outputListeners.size).toBe(0);
  });
});
