'use strict';

function promptTokenForMac(mac) {
  return `(${mac})> `;
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
      if (previous !== '\n' && previous !== '\r') {
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
  promptTokenForMac,
};
