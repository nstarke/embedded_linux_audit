'use strict';

const { runExec } = require('../../../../api/terminal/execCommand');

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

describe('runExec', () => {
  const mac = 'aa:bb:cc:dd:ee:ff';

  test('sends a wrapped command and resolves on the next prompt', async () => {
    const entry = createEntry();
    let clock = 1000;
    const promise = runExec({
      entry,
      mac,
      command: 'echo hi',
      now: () => clock,
    });

    expect(entry.sent).toEqual(['linux execute-command "echo hi"\n']);
    expect(entry.outputListeners.size).toBe(1);

    clock = 1005;
    entry.emit('hi\r\n');
    entry.emit(`(${mac})> `);

    const result = await promise;
    expect(result).toEqual({ ok: true, output: 'hi', durationMs: 5 });
    // listener is cleaned up after completion
    expect(entry.outputListeners.size).toBe(0);
  });

  test('rejects with NOT_CONNECTED when the socket is closed', async () => {
    const entry = createEntry({ readyState: 3 });
    await expect(runExec({ entry, mac, command: 'ls' })).rejects.toMatchObject({ code: 'NOT_CONNECTED' });
    expect(entry.sent).toEqual([]);
  });

  test('rejects with TIMEOUT and partial output when no prompt arrives', async () => {
    const entry = createEntry();
    const timers = [];
    let clock = 0;
    const promise = runExec({
      entry,
      mac,
      command: 'sleep 5',
      timeoutMs: 100,
      now: () => clock,
      setTimeoutImpl: (fn) => {
        timers.push(fn);
        return 1;
      },
      clearTimeoutImpl: () => {},
    });

    entry.emit('partial output');
    clock = 100;
    timers[0]();

    await expect(promise).rejects.toMatchObject({
      code: 'TIMEOUT',
      output: 'partial output',
      durationMs: 100,
    });
    expect(entry.outputListeners.size).toBe(0);
  });

  test('ignores output that arrives after settling', async () => {
    const entry = createEntry();
    const promise = runExec({ entry, mac, command: 'ls', now: () => 0 });

    entry.emit(`done\r\n(${mac})> `);
    await promise;

    // Late output must not throw now that the listener is detached.
    expect(() => entry.emit('late')).not.toThrow();
  });
});
