'use strict';

const {
  DEFAULT_MAX_BATCH_LINES,
  appendBatchOutput,
  getBatchOutputLabel,
  normalizeBatchOutputLines,
  renderBatchOutput,
} = require('../../../../api/terminal/batchOutput');

describe('terminal batch output helpers', () => {
  test('prefers alias labels when available', () => {
    expect(getBatchOutputLabel({ mac: 'aa-bb', alias: 'router' })).toBe('router (aa-bb)');
    expect(getBatchOutputLabel({ mac: 'aa-bb', alias: null })).toBe('aa-bb');
  });

  test('normalizes line endings and removes prompt-only output', () => {
    expect(normalizeBatchOutputLines('hello\r\n(aa-bb)> \r\nworld\r', 'aa-bb')).toEqual([
      'hello',
      'world',
    ]);
  });

  test('prefixes node output with the session label', () => {
    expect(appendBatchOutput([], { mac: 'aa-bb', alias: 'router' }, 'hello\nworld')).toEqual([
      '[router (aa-bb)] hello',
      '[router (aa-bb)] world',
    ]);
  });

  test('retains only the most recent lines', () => {
    const lines = appendBatchOutput(
      ['[old] one', '[old] two'],
      { mac: 'aa-bb', alias: null },
      'three\nfour',
      { maxLines: 3 },
    );

    expect(lines).toEqual([
      '[old] two',
      '[aa-bb] three',
      '[aa-bb] four',
    ]);
    expect(DEFAULT_MAX_BATCH_LINES).toBeGreaterThan(0);
  });

  test('renders a readable multi-line block', () => {
    expect(renderBatchOutput(['[aa-bb] hello', '[cc-dd] world'])).toBe(
      'Recent batch output:\r\n  [aa-bb] hello\r\n  [cc-dd] world',
    );
  });
});
