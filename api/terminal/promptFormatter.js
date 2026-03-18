'use strict';

function promptTokenForMac(mac) {
  return `(${mac})> `;
}

function hasPromptRedrawPrefix(input, index) {
  const prefix = input.slice(Math.max(0, index - 8), index);
  return prefix.endsWith('\r')
    || prefix.endsWith('\x1b[2K')
    || prefix.endsWith('\r\x1b[2K')
    || prefix.endsWith('\x1b[K')
    || prefix.endsWith('\r\x1b[K');
}

function formatPromptOutput(text, mac) {
  const token = promptTokenForMac(mac);
  let index = 0;
  let result = '';
  let searchFrom = 0;
  const input = String(text || '');

  while ((index = input.indexOf(token, searchFrom)) >= 0) {
    result += input.slice(searchFrom, index);
    if (index > 0) {
      const previous = input[index - 1];
      if (previous !== '\n' && previous !== '\r' && !hasPromptRedrawPrefix(input, index)) {
        result += '\r\n';
      }
    }
    result += token;
    searchFrom = index + token.length;
  }

  result += input.slice(searchFrom);
  return result;
}

module.exports = {
  formatPromptOutput,
  hasPromptRedrawPrefix,
  promptTokenForMac,
};
