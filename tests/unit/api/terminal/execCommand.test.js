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

  test('does not settle on the input-echo prompt, and returns clean output', async () => {
    // Reproduces the interactive REPL: the agent redraws the prompt while the
    // command is "typed" (each redraw contains the prompt token but is NOT a
    // completion), then echoes the full command, then the real output, then a
    // fresh prompt on its own line.
    const entry = createEntry();
    const promise = runExec({ entry, mac, command: 'uname -a', now: () => 0 });

    entry.emit(`\r\x1b[2K(${mac})> l`);
    entry.emit(`\r\x1b[2K(${mac})> lin`);
    entry.emit(`\r\x1b[2K(${mac})> linux execute-command "uname -a"`);
    // These redraw prompts must not have resolved the promise.
    let done = false;
    promise.then(() => { done = true; });
    await Promise.resolve();
    expect(done).toBe(false);

    entry.emit('\r\n');
    entry.emit('Linux host 5.10.0 #1 SMP x86_64\r\n');
    entry.emit(`(${mac})> `); // completion prompt (preceded by newline)

    const result = await promise;
    expect(result.ok).toBe(true);
    expect(result.output).toBe('Linux host 5.10.0 #1 SMP x86_64');
  });

  test('sends the raw command when wrapShell is false (ELA agent command)', () => {
    const entry = createEntry();
    // Stub the timer so the un-awaited promise does not schedule a real timeout.
    const p = runExec({
      entry, mac, command: 'linux gdbserver tunnel 42 wss://h', wrapShell: false, now: () => 0,
      setTimeoutImpl: () => 1, clearTimeoutImpl: () => {},
    });
    p.catch(() => {});
    expect(entry.sent).toEqual(['linux gdbserver tunnel 42 wss://h\n']);
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
