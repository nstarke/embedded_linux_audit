'use strict';

const {
  formatPromptOutput,
  hasPromptRedrawPrefix,
  promptTokenForMac,
} = require('../../../../api/terminal/promptFormatter');

describe('terminal prompt formatter', () => {
  test('leaves a prompt at the start of output unchanged', () => {
    expect(formatPromptOutput('(aa:bb)> ', 'aa:bb')).toBe('(aa:bb)> ');
  });

  test('moves a prompt onto a new line when command output does not end with one', () => {
    expect(formatPromptOutput(`hello${promptTokenForMac('aa:bb')}`, 'aa:bb')).toBe(`hello\r\n${promptTokenForMac('aa:bb')}`);
  });

  test('does not add an extra newline when prompt is already on its own line', () => {
    expect(formatPromptOutput(`hello\n${promptTokenForMac('aa:bb')}`, 'aa:bb')).toBe(`hello\n${promptTokenForMac('aa:bb')}`);
  });

  test('does not add a newline for interactive prompt redraw control sequences', () => {
    expect(formatPromptOutput(`\r\x1b[2K${promptTokenForMac('aa:bb')}s`, 'aa:bb')).toBe(`\r\x1b[2K${promptTokenForMac('aa:bb')}s`);
  });

  test('detects prompt redraw prefixes', () => {
    const input = `\r\x1b[2K${promptTokenForMac('aa:bb')}`;
    expect(hasPromptRedrawPrefix(input, input.indexOf(promptTokenForMac('aa:bb')))).toBe(true);
  });
});
