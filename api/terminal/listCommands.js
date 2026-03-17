'use strict';

function parseListCommand(input) {
  const trimmed = String(input || '').trim();
  if (!trimmed) {
    return { type: 'empty' };
  }

  if (trimmed === 'update-all') {
    return { type: 'update-all' };
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
