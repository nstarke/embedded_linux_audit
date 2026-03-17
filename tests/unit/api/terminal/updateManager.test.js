'use strict';

const {
  buildIsaString,
  startSessionUpdate,
  handleUpdateMessage,
} = require('../../../../api/terminal/updateManager');

describe('update manager', () => {
  test('buildIsaString applies endianness suffix where needed', () => {
    expect(buildIsaString('x86_64', 'little')).toBe('x86_64');
    expect(buildIsaString('arm32', 'big')).toBe('arm32-be');
    expect(buildIsaString('aarch64', 'little')).toBe('aarch64-le');
  });

  test('startSessionUpdate primes the state machine and sends isa probe', () => {
    const ws = { OPEN: 1, readyState: 1, send: jest.fn() };
    const entry = { ws, updateCtx: null, updateStatus: null };

    expect(startSessionUpdate(entry, 'https://example.test')).toBe(true);
    expect(entry.updateStatus).toBe('updating');
    expect(entry.updateCtx.state).toBe('await-isa');
    expect(ws.send).toHaveBeenNthCalledWith(1, '\x15');
    expect(ws.send).toHaveBeenNthCalledWith(2, '--output-format json arch isa\n');
  });

  test('handleUpdateMessage advances through isa and endianness to download', () => {
    const ws = { OPEN: 1, readyState: 1, send: jest.fn() };
    const entry = { ws, updateCtx: null, updateStatus: null, mac: 'aa:bb' };
    startSessionUpdate(entry, 'https://updates.example');
    ws.send.mockClear();

    handleUpdateMessage(entry, '{"record":"arch","subcommand":"isa","value":"arm32"}\n', {
      updateUrl: 'https://updates.example',
    });
    expect(entry.updateCtx.state).toBe('await-endianness');
    expect(ws.send).toHaveBeenCalledWith('--output-format json arch endianness\n');

    ws.send.mockClear();
    handleUpdateMessage(entry, '{"record":"arch","subcommand":"endianness","value":"big"}\n', {
      updateUrl: 'https://updates.example',
    });
    expect(entry.updateCtx.state).toBe('in-progress');
    expect(ws.send.mock.calls[0][0]).toContain('linux download-file https://updates.example/isa/arm32-be /tmp/ela.new');
  });

  test('handleUpdateMessage marks successful completion', () => {
    const entry = {
      ws: { OPEN: 1, readyState: 1, send: jest.fn() },
      updateCtx: { state: 'in-progress', buffer: '' },
      updateStatus: 'updating',
      mac: 'aa:bb',
    };
    const onComplete = jest.fn();

    handleUpdateMessage(entry, 'done [UPDATE OK]', {
      updateUrl: 'https://updates.example',
      onUpdateComplete: onComplete,
    });

    expect(entry.updateCtx).toBeNull();
    expect(entry.updateStatus).toBe('ok');
    expect(onComplete).toHaveBeenCalledWith(entry);
  });
});
