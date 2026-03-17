'use strict';

const { executeLocalSessionCommand } = require('../../../../api/terminal/localCommands');

describe('local terminal commands', () => {
  test('handles detach locally', async () => {
    const onDetach = jest.fn();
    const writeOutput = jest.fn();
    const cancelRemoteInput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/detach',
      activeMac: 'aa:bb',
      sessionEntry: {},
      setDeviceAlias: jest.fn(),
      onDetach,
      writeOutput,
      cancelRemoteInput,
    });

    expect(handled).toBe(true);
    expect(cancelRemoteInput).toHaveBeenCalled();
    expect(onDetach).toHaveBeenCalled();
  });

  test('handles alias writes through injected persistence', async () => {
    const sessionEntry = { alias: null };
    const setDeviceAlias = jest.fn().mockResolvedValue(undefined);
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/name core-router',
      activeMac: 'aa:bb',
      sessionEntry,
      setDeviceAlias,
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(setDeviceAlias).toHaveBeenCalledWith('aa:bb', 'core-router', 'terminal_api');
    expect(sessionEntry.alias).toBe('core-router');
    expect(writeOutput).toHaveBeenCalledWith('\r\n[alias set to "core-router"]\r\n');
  });

  test('handles update command with configured update URL', async () => {
    const sessionEntry = { alias: null, ws: { OPEN: 1, readyState: 1, send: jest.fn() } };
    const startUpdate = jest.fn().mockReturnValue(true);
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/update',
      activeMac: 'aa:bb',
      sessionEntry,
      sessions: [sessionEntry],
      setDeviceAlias: jest.fn(),
      updateUrl: 'https://updates.example',
      startSessionUpdate: startUpdate,
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(startUpdate).toHaveBeenCalledWith(sessionEntry, 'https://updates.example');
    expect(writeOutput).toHaveBeenCalledWith('\r\n[update: detecting architecture...]\r\n');
  });

  test('handles exit-all by broadcasting exit to all sessions', async () => {
    const a = { ws: { OPEN: 1, readyState: 1, send: jest.fn() } };
    const b = { ws: { OPEN: 1, readyState: 1, send: jest.fn() } };
    const onDetach = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/exit-all',
      activeMac: 'aa:bb',
      sessionEntry: a,
      sessions: [a, b],
      setDeviceAlias: jest.fn(),
      onDetach,
      writeOutput: jest.fn(),
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(a.ws.send).toHaveBeenCalledWith('exit\n');
    expect(b.ws.send).toHaveBeenCalledWith('exit\n');
    expect(onDetach).toHaveBeenCalled();
  });
});
