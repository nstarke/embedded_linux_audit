'use strict';

async function executeLocalSessionCommand({
  cmd,
  activeMac,
  sessionEntry,
  sessions = [],
  setDeviceAlias,
  startSessionUpdate = () => false,
  onDetach,
  writeOutput,
  cancelRemoteInput,
}) {
  if (cmd === '/detach') {
    cancelRemoteInput();
    writeOutput('\r\n');
    onDetach();
    return true;
  }

  if (cmd === '/exit-all') {
    cancelRemoteInput();
    for (const entry of sessions) {
      if (entry.ws.readyState === entry.ws.OPEN) {
        entry.ws.send('exit\n');
      }
    }
    writeOutput('\r\n');
    onDetach();
    return true;
  }

  if (cmd === '/update') {
    if (!sessionEntry || !startSessionUpdate(sessionEntry)) {
      cancelRemoteInput();
      writeOutput('\r\n[update: already in progress]\r\n');
      return true;
    }
    writeOutput('\r\n[update: detecting architecture...]\r\n');
    return true;
  }

  if (cmd === '/shell') {
    cancelRemoteInput();
    if (!sessionEntry || sessionEntry.ws.readyState !== sessionEntry.ws.OPEN) {
      writeOutput('\r\n[shell: session is not connected]\r\n');
      return true;
    }

    sessionEntry.inputMode = 'passthrough';
    sessionEntry.ws.send('linux execute-command sh\n');
    writeOutput('\r\n[passthrough mode enabled; launched linux execute-command sh]\r\n');
    return true;
  }

  if (cmd === '/name' || cmd.startsWith('/name ')) {
    cancelRemoteInput();
    const alias = cmd.slice(6).trim() || null;
    await setDeviceAlias(activeMac, alias, 'terminal_api');
    if (sessionEntry) {
      sessionEntry.alias = alias;
    }
    writeOutput(`\r\n[alias ${alias ? `set to "${alias}"` : 'cleared'}]\r\n`);
    return true;
  }

  return false;
}

module.exports = {
  executeLocalSessionCommand,
};
