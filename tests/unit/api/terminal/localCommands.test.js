'use strict';

const {
  SESSION_COMMAND_HELP,
  executeLocalSessionCommand,
} = require('../../../../api/terminal/localCommands');

describe('local terminal commands', () => {
  test('handles help locally for the attached session', async () => {
    const writeOutput = jest.fn();
    const cancelRemoteInput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/help',
      activeMac: 'aa:bb',
      sessionEntry: {},
      setDeviceAlias: jest.fn(),
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput,
    });

    expect(handled).toBe(true);
    expect(cancelRemoteInput).toHaveBeenCalled();
    expect(writeOutput).toHaveBeenCalledWith(`\r\n${SESSION_COMMAND_HELP.join('\r\n')}\r\n`);
  });

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
      startSessionUpdate: startUpdate,
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(startUpdate).toHaveBeenCalledWith(sessionEntry);
    expect(writeOutput).toHaveBeenCalledWith('\r\n[update: detecting architecture...]\r\n');
  });

  test('handles shell command by launching execute-command sh and enabling passthrough', async () => {
    const sessionEntry = { inputMode: 'line', ws: { OPEN: 1, readyState: 1, send: jest.fn() } };
    const writeOutput = jest.fn();
    const cancelRemoteInput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/shell',
      activeMac: 'aa:bb',
      sessionEntry,
      setDeviceAlias: jest.fn(),
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput,
    });

    expect(handled).toBe(true);
    expect(cancelRemoteInput).toHaveBeenCalled();
    expect(sessionEntry.inputMode).toBe('passthrough');
    expect(sessionEntry.ws.send).toHaveBeenCalledWith('linux execute-command sh\n');
    expect(writeOutput).toHaveBeenCalledWith('\r\n[passthrough mode enabled; launched linux execute-command sh]\r\n');
  });

  test('does not intercept /exit in an attached session', async () => {
    const handled = await executeLocalSessionCommand({
      cmd: '/exit',
      activeMac: 'aa:bb',
      sessionEntry: { ws: { OPEN: 1, readyState: 1, send: jest.fn() } },
      setDeviceAlias: jest.fn(),
      onDetach: jest.fn(),
      writeOutput: jest.fn(),
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(false);
  });
});
