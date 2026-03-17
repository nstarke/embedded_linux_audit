'use strict';

const LIST_COMMAND_HELP = [
  '/help                          show commands available in the top-level session list',
  '/update                        update all connected nodes using each node\'s ELA_API_URL',
  '/shell <command>               run linux execute-command <command> on all connected nodes after confirmation',
  '/cmd <command>                 run a raw agent command on all connected nodes after confirmation',
  '/set <key> <value>             set an agent environment variable on all connected nodes',
  '/exit                          run exit on all connected nodes after confirmation',
];

function formatListCommandHelp() {
  return [
    'Top-level commands:',
    ...LIST_COMMAND_HELP.map((line) => `  ${line}`),
  ].join('\r\n');
}

function parseListCommand(input) {
  const trimmed = String(input || '').trim();
  if (!trimmed) {
    return { type: 'empty' };
  }

  if (trimmed === 'help') {
    return { type: 'help' };
  }

  if (trimmed === 'update') {
    return { type: 'update' };
  }

  if (trimmed === 'exit') {
    return { type: 'exit' };
  }

  if (trimmed === 'shell') {
    return { type: 'invalid-shell' };
  }

  if (trimmed.startsWith('shell ')) {
    let command = trimmed.slice(6).trim();
    if (!command) {
      return { type: 'invalid-shell' };
    }
    if (command.length >= 2) {
      const first = command[0];
      const last = command[command.length - 1];
      if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
        command = command.slice(1, -1).trim();
      }
    }
    return command
      ? { type: 'shell-all', command }
      : { type: 'invalid-shell' };
  }

  if (trimmed === 'cmd') {
    return { type: 'invalid-cmd' };
  }

  if (trimmed.startsWith('cmd ')) {
    let command = trimmed.slice(4).trim();
    if (!command) {
      return { type: 'invalid-cmd' };
    }
    if (command.length >= 2) {
      const first = command[0];
      const last = command[command.length - 1];
      if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
        command = command.slice(1, -1).trim();
      }
    }
    return command
      ? { type: 'cmd-all', command }
      : { type: 'invalid-cmd' };
  }

  if (trimmed === 'set' || trimmed.startsWith('set ')) {
    const remainder = trimmed.slice(3).trim();
    if (!remainder) {
      return { type: 'invalid-set' };
    }

    const firstSpace = remainder.indexOf(' ');
    if (firstSpace < 0) {
      return { type: 'invalid-set' };
    }

    const key = remainder.slice(0, firstSpace).trim();
    const value = remainder.slice(firstSpace + 1).trim();
    if (!key || !value) {
      return { type: 'invalid-set' };
    }

    return { type: 'set-all', key, value };
  }

  return { type: 'unknown', raw: trimmed };
}

function isAffirmativeResponse(input) {
  const normalized = String(input || '').trim().toLowerCase();
  return normalized === 'y' || normalized === 'yes';
}

module.exports = {
  formatListCommandHelp,
  LIST_COMMAND_HELP,
  isAffirmativeResponse,
  parseListCommand,
};
