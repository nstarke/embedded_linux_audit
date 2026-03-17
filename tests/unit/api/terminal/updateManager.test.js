'use strict';

const {
  buildIsaString,
  deriveUpdateBaseUrl,
  startSessionUpdate,
  handleUpdateMessage,
} = require('../../../../api/terminal/updateManager');

describe('update manager', () => {
  test('buildIsaString applies endianness suffix where needed', () => {
    expect(buildIsaString('x86_64', 'little')).toBe('x86_64');
    expect(buildIsaString('arm32', 'big')).toBe('arm32-be');
    expect(buildIsaString('aarch64', 'little')).toBe('aarch64-le');
  });

  test('deriveUpdateBaseUrl strips trailing upload route from ELA_API_URL', () => {
    expect(deriveUpdateBaseUrl('https://ela.example.com/upload')).toBe('https://ela.example.com');
    expect(deriveUpdateBaseUrl('https://ela.example.com/api/agent/upload')).toBe('https://ela.example.com/api/agent');
    expect(deriveUpdateBaseUrl('ftp://ela.example.com/upload')).toBeNull();
  });

  test('startSessionUpdate primes the state machine and requests the node api url', () => {
    const ws = { OPEN: 1, readyState: 1, send: jest.fn() };
    const entry = { ws, updateCtx: null, updateStatus: null };

    expect(startSessionUpdate(entry)).toBe(true);
    expect(entry.updateStatus).toBe('updating');
    expect(entry.updateCtx.state).toBe('await-api-url');
    expect(ws.send).toHaveBeenNthCalledWith(1, '\x15');
    expect(ws.send).toHaveBeenNthCalledWith(
      2,
      'linux execute-command "printf \'[ELA_API_URL_BEGIN]%s[ELA_API_URL_END]\' \\"$ELA_API_URL\\""\n',
    );
  });

  test('handleUpdateMessage advances through api url, isa, and endianness to download', () => {
    const ws = { OPEN: 1, readyState: 1, send: jest.fn() };
    const entry = { ws, updateCtx: null, updateStatus: null, mac: 'aa:bb' };
    startSessionUpdate(entry);
    ws.send.mockClear();

    handleUpdateMessage(entry, '[ELA_API_URL_BEGIN]https://updates.example/upload[ELA_API_URL_END]');
    expect(entry.updateCtx.state).toBe('await-isa');
    expect(ws.send).toHaveBeenCalledWith('--output-format json arch isa\n');

    ws.send.mockClear();
    handleUpdateMessage(entry, '{"record":"arch","subcommand":"isa","value":"arm32"}\n');
    expect(entry.updateCtx.state).toBe('await-endianness');
    expect(ws.send).toHaveBeenCalledWith('--output-format json arch endianness\n');

    ws.send.mockClear();
    handleUpdateMessage(entry, '{"record":"arch","subcommand":"endianness","value":"big"}\n');
    expect(entry.updateCtx.state).toBe('in-progress');
    expect(ws.send.mock.calls[0][0]).toContain('linux download-file https://updates.example/isa/arm32-be /tmp/ela.new');
  });

  test('handleUpdateMessage fails when the node api url is missing', () => {
    const entry = {
      ws: { OPEN: 1, readyState: 1, send: jest.fn() },
      updateCtx: { state: 'await-api-url', buffer: '' },
      updateStatus: 'updating',
    };
    const onFailed = jest.fn();

    handleUpdateMessage(entry, '[ELA_API_URL_BEGIN][ELA_API_URL_END]', {
      onUpdateFailed: onFailed,
    });

    expect(entry.updateCtx).toBeNull();
    expect(entry.updateStatus).toBe('failed');
    expect(onFailed).toHaveBeenCalledWith(entry);
  });

  test('handleUpdateMessage marks successful completion', () => {
    const entry = {
      ws: { OPEN: 1, readyState: 1, send: jest.fn() },
      updateCtx: { state: 'in-progress', buffer: '' },
      updateStatus: 'updating',
      mac: 'aa:bb',
    };
    const onComplete = jest.fn();

    handleUpdateMessage(entry, 'done [UPDATE OK]', { onUpdateComplete: onComplete });

    expect(entry.updateCtx).toBeNull();
    expect(entry.updateStatus).toBe('ok');
    expect(onComplete).toHaveBeenCalledWith(entry);
  });
});
