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
