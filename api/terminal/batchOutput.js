'use strict';

const { promptTokenForMac } = require('./promptFormatter');

const DEFAULT_MAX_BATCH_LINES = 80;

function getBatchOutputLabel(entry) {
  if (!entry) {
    return 'unknown';
  }

  return entry.alias ? `${entry.alias} (${entry.mac})` : entry.mac;
}

function normalizeBatchOutputLines(text, mac) {
  const prompt = promptTokenForMac(mac).trimEnd();
  return String(text || '')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line) => line && line !== prompt);
}

function appendBatchOutput(existingLines, entry, text, { maxLines = DEFAULT_MAX_BATCH_LINES } = {}) {
  const nextLines = [...existingLines];
  const label = getBatchOutputLabel(entry);

  for (const line of normalizeBatchOutputLines(text, entry?.mac)) {
    nextLines.push(`[${label}] ${line}`);
  }

  if (nextLines.length <= maxLines) {
    return nextLines;
  }

  return nextLines.slice(nextLines.length - maxLines);
}

function renderBatchOutput(lines) {
  if (!Array.isArray(lines) || lines.length === 0) {
    return '';
  }

  return [
    'Recent batch output:',
    ...lines.map((line) => `  ${line}`),
  ].join('\r\n');
}

module.exports = {
  DEFAULT_MAX_BATCH_LINES,
  appendBatchOutput,
  getBatchOutputLabel,
  normalizeBatchOutputLines,
  renderBatchOutput,
};
