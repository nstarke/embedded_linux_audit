'use strict';

async function executeLocalSessionCommand({
  cmd,
  activeMac,
  sessionEntry,
  setDeviceAlias,
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
