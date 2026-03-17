'use strict';

async function executeLocalSessionCommand({
  cmd,
  activeMac,
  sessionEntry,
  sessions = [],
  setDeviceAlias,
  updateUrl = '',
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
    if (!updateUrl) {
      cancelRemoteInput();
      writeOutput('\r\n[update: ELA_UPDATE_URL is not set]\r\n');
      return true;
    }
    if (!sessionEntry || !startSessionUpdate(sessionEntry, updateUrl)) {
      cancelRemoteInput();
      writeOutput('\r\n[update: already in progress]\r\n');
      return true;
    }
    writeOutput('\r\n[update: detecting architecture...]\r\n');
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
