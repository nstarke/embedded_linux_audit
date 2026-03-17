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
});
