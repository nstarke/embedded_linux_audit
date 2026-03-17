'use strict';

const PASSTHROUGH_EXIT_SEQUENCE = '\x1d';
const PASSTHROUGH_EXIT_HINT = 'Ctrl-]';

const SHELL_NAMES = new Set([
  'sh',
  'ash',
  'bash',
  'dash',
  'ksh',
  'zsh',
]);

function stripOuterQuotes(value) {
  if (!value || value.length < 2) {
    return value;
  }

  const first = value[0];
  const last = value[value.length - 1];
  if ((first === '"' && last === '"') || (first === '\'' && last === '\'')) {
    return value.slice(1, -1);
  }

  return value;
}

function tokenizeCommand(value) {
  return String(value || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

function isShellToken(token) {
  if (!token) {
    return false;
  }

  const normalized = token.toLowerCase();
  if (SHELL_NAMES.has(normalized)) {
    return true;
  }

  const leaf = normalized.split('/').pop();
  return SHELL_NAMES.has(leaf);
}

function shouldEnterPassthrough(commandLine) {
  const prefix = 'linux execute-command ';
  if (!String(commandLine || '').startsWith(prefix)) {
    return false;
  }

  const command = stripOuterQuotes(String(commandLine).slice(prefix.length).trim());
  const tokens = tokenizeCommand(command);
  if (!tokens.length) {
    return false;
  }

  if (isShellToken(tokens[0])) {
    return true;
  }

  if (tokens[0] === 'exec' && isShellToken(tokens[1])) {
    return true;
  }

  if ((tokens[0] === 'busybox' || tokens[0].endsWith('/busybox')) && isShellToken(tokens[1])) {
    return true;
  }

  return false;
}

function remoteInputForKeypress(key, name) {
  if (name === 'return') {
    return '\n';
  }
  if (name === 'backspace') {
    return '\x7f';
  }
  if (name === 'tab') {
    return '\t';
  }
  if (name === 'up') {
    return '\x1b[A';
  }
  if (name === 'down') {
    return '\x1b[B';
  }
  if (name === 'left') {
    return '\x1b[D';
  }
  if (name === 'right') {
    return '\x1b[C';
  }
  if (key) {
    return key === '\r' ? '\n' : key;
  }
  return null;
}

module.exports = {
  PASSTHROUGH_EXIT_HINT,
  PASSTHROUGH_EXIT_SEQUENCE,
  remoteInputForKeypress,
  shouldEnterPassthrough,
};
