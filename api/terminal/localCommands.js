'use strict';

const { parseCidr } = require('./cidrUtil');

const SESSION_COMMAND_HELP = [
  '/help                          show commands available for the attached session',
  '/detach                        return to the top-level session list',
  '/update                        update only the currently attached node',
  '/shell                         launch linux execute-command sh and enter passthrough mode',
  '/name [alias]                  set or clear the alias for the current node',
  '/group [group]                 set or clear the group for the current node',
  '/delete <group> <name>         delete an alias by group and name',
  '/block [<ip>[/<prefix>]]        block an IP/CIDR, or list all blocked ranges',
];

async function executeLocalSessionCommand({
  cmd,
  activeMac,
  sessionEntry,
  sessions = [],
  setDeviceAlias,
  setDeviceGroup = () => {},
  deleteDeviceAliasByGroupAndName = () => Promise.resolve(false),
  addBlock = () => Promise.resolve(false),
  getBlockList = () => [],
  startSessionUpdate = () => false,
  onDetach,
  writeOutput,
  cancelRemoteInput,
}) {
  if (cmd === '/help') {
    cancelRemoteInput();
    writeOutput(`\r\n${SESSION_COMMAND_HELP.join('\r\n')}\r\n`);
    return true;
  }

  if (cmd === '/detach') {
    cancelRemoteInput();
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

  if (cmd === '/group' || cmd.startsWith('/group ')) {
    cancelRemoteInput();
    const group = cmd.slice(7).trim() || null;
    await setDeviceGroup(activeMac, group);
    if (sessionEntry) {
      sessionEntry.group = group;
    }
    writeOutput(`\r\n[group ${group ? `set to "${group}"` : 'cleared'}]\r\n`);
    return true;
  }

  if (cmd.startsWith('/delete ')) {
    cancelRemoteInput();
    const trimmed = cmd.slice(8).trim();
    const spaceIdx = trimmed.indexOf(' ');
    if (spaceIdx === -1) {
      writeOutput('\r\n[usage: /delete <group> <name>]\r\n');
      return true;
    }
    const group = trimmed.slice(0, spaceIdx);
    const name = trimmed.slice(spaceIdx + 1).trim();
    if (!name) {
      writeOutput('\r\n[usage: /delete <group> <name>]\r\n');
      return true;
    }
    const deleted = await deleteDeviceAliasByGroupAndName(group, name);
    if (deleted) {
      for (const s of sessions) {
        if (s.alias === name && s.group === group) {
          s.alias = null;
        }
      }
      writeOutput(`\r\n[alias "${name}" in group "${group}" deleted]\r\n`);
    } else {
      writeOutput(`\r\n[not found: "${name}" in group "${group}"]\r\n`);
    }
    return true;
  }

  if (cmd === '/block') {
    cancelRemoteInput();
    const list = getBlockList();
    if (list.length === 0) {
      writeOutput('\r\n[no blocked ranges]\r\n');
    } else {
      writeOutput(`\r\n[blocked ranges]\r\n${list.join('\r\n')}\r\n`);
    }
    return true;
  }

  if (cmd.startsWith('/block ')) {
    cancelRemoteInput();
    const input = cmd.slice(7).trim();
    const parsed = parseCidr(input);
    if (!parsed) {
      writeOutput('\r\n[usage: /block <ip-address>[/<prefix>]]\r\n');
      return true;
    }
    const created = await addBlock(parsed.cidr);
    writeOutput(created
      ? `\r\n[blocked: ${parsed.cidr}]\r\n`
      : `\r\n[already blocked: ${parsed.cidr}]\r\n`
    );
    return true;
  }

  return false;
}

module.exports = {
  SESSION_COMMAND_HELP,
  executeLocalSessionCommand,
};
