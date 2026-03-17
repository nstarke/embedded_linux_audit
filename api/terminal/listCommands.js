'use strict';

function parseListCommand(input) {
  const trimmed = String(input || '').trim();
  if (!trimmed) {
    return { type: 'empty' };
  }

  if (trimmed === 'update') {
    return { type: 'update' };
  }

  if (trimmed === 'shell') {
    return { type: 'invalid-shell' };
  }

  if (trimmed.startsWith('shell ')) {
    const command = trimmed.slice(6).trim();
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
  isAffirmativeResponse,
  parseListCommand,
};
