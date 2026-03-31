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

  test('handles group writes through injected persistence', async () => {
    const sessionEntry = { group: null };
    const setDeviceGroup = jest.fn().mockResolvedValue(undefined);
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/group factory-floor',
      activeMac: 'aa:bb',
      sessionEntry,
      setDeviceAlias: jest.fn(),
      setDeviceGroup,
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(setDeviceGroup).toHaveBeenCalledWith('aa:bb', 'factory-floor');
    expect(sessionEntry.group).toBe('factory-floor');
    expect(writeOutput).toHaveBeenCalledWith('\r\n[group set to "factory-floor"]\r\n');
  });

  test('handles delete command when alias is found', async () => {
    const matchingSession = { alias: 'edge-router', group: 'factory-floor' };
    const otherSession = { alias: 'switch', group: 'factory-floor' };
    const deleteDeviceAliasByGroupAndName = jest.fn().mockResolvedValue(true);
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/delete factory-floor edge-router',
      activeMac: 'aa:bb',
      sessionEntry: {},
      sessions: [matchingSession, otherSession],
      setDeviceAlias: jest.fn(),
      deleteDeviceAliasByGroupAndName,
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(deleteDeviceAliasByGroupAndName).toHaveBeenCalledWith('factory-floor', 'edge-router');
    expect(matchingSession.alias).toBeNull();
    expect(otherSession.alias).toBe('switch');
    expect(writeOutput).toHaveBeenCalledWith('\r\n[alias "edge-router" in group "factory-floor" deleted]\r\n');
  });

  test('handles delete command when alias is not found', async () => {
    const deleteDeviceAliasByGroupAndName = jest.fn().mockResolvedValue(false);
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/delete factory-floor nonexistent',
      activeMac: 'aa:bb',
      sessionEntry: {},
      sessions: [],
      setDeviceAlias: jest.fn(),
      deleteDeviceAliasByGroupAndName,
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(writeOutput).toHaveBeenCalledWith('\r\n[not found: "nonexistent" in group "factory-floor"]\r\n');
  });

  test('handles delete command with missing name argument', async () => {
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/delete factory-floor',
      activeMac: 'aa:bb',
      sessionEntry: {},
      sessions: [],
      setDeviceAlias: jest.fn(),
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(writeOutput).toHaveBeenCalledWith('\r\n[usage: /delete <group> <name>]\r\n');
  });

  test('handles block with a valid IP address', async () => {
    const addBlock = jest.fn().mockResolvedValue(true);
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/block 10.0.0.1',
      activeMac: 'aa:bb',
      sessionEntry: {},
      setDeviceAlias: jest.fn(),
      addBlock,
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(addBlock).toHaveBeenCalledWith('10.0.0.1/32');
    expect(writeOutput).toHaveBeenCalledWith('\r\n[blocked: 10.0.0.1/32]\r\n');
  });

  test('handles block with a CIDR range', async () => {
    const addBlock = jest.fn().mockResolvedValue(true);
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/block 192.168.0.0/16',
      activeMac: 'aa:bb',
      sessionEntry: {},
      setDeviceAlias: jest.fn(),
      addBlock,
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(addBlock).toHaveBeenCalledWith('192.168.0.0/16');
    expect(writeOutput).toHaveBeenCalledWith('\r\n[blocked: 192.168.0.0/16]\r\n');
  });

  test('handles block when the address is already blocked', async () => {
    const addBlock = jest.fn().mockResolvedValue(false);
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/block 10.0.0.1',
      activeMac: 'aa:bb',
      sessionEntry: {},
      setDeviceAlias: jest.fn(),
      addBlock,
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(writeOutput).toHaveBeenCalledWith('\r\n[already blocked: 10.0.0.1/32]\r\n');
  });

  test('handles block with no arguments and an empty list', async () => {
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/block',
      activeMac: 'aa:bb',
      sessionEntry: {},
      setDeviceAlias: jest.fn(),
      getBlockList: () => [],
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(writeOutput).toHaveBeenCalledWith('\r\n[no blocked ranges]\r\n');
  });

  test('handles block with no arguments and an existing list', async () => {
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/block',
      activeMac: 'aa:bb',
      sessionEntry: {},
      setDeviceAlias: jest.fn(),
      getBlockList: () => ['10.0.0.1/32', '192.168.0.0/16'],
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(writeOutput).toHaveBeenCalledWith('\r\n[blocked ranges]\r\n10.0.0.1/32\r\n192.168.0.0/16\r\n');
  });

  test('handles block with an invalid IP address', async () => {
    const addBlock = jest.fn();
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/block not-an-ip',
      activeMac: 'aa:bb',
      sessionEntry: {},
      setDeviceAlias: jest.fn(),
      addBlock,
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(addBlock).not.toHaveBeenCalled();
    expect(writeOutput).toHaveBeenCalledWith('\r\n[usage: /block <ip-address>[/<prefix>]]\r\n');
  });

  test('handles group clear', async () => {
    const sessionEntry = { group: 'factory-floor' };
    const setDeviceGroup = jest.fn().mockResolvedValue(undefined);
    const writeOutput = jest.fn();

    const handled = await executeLocalSessionCommand({
      cmd: '/group',
      activeMac: 'aa:bb',
      sessionEntry,
      setDeviceAlias: jest.fn(),
      setDeviceGroup,
      onDetach: jest.fn(),
      writeOutput,
      cancelRemoteInput: jest.fn(),
    });

    expect(handled).toBe(true);
    expect(setDeviceGroup).toHaveBeenCalledWith('aa:bb', null);
    expect(sessionEntry.group).toBeNull();
    expect(writeOutput).toHaveBeenCalledWith('\r\n[group cleared]\r\n');
  });
});
