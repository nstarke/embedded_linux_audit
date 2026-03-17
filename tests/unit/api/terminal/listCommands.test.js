'use strict';

const {
  isAffirmativeResponse,
  parseListCommand,
} = require('../../../../api/terminal/listCommands');

describe('terminal list command helpers', () => {
  test('parses update-all and shell batch commands', () => {
    expect(parseListCommand('update-all')).toEqual({ type: 'update-all' });
    expect(parseListCommand('shell uname -a')).toEqual({
      type: 'shell-all',
      command: 'uname -a',
    });
    expect(parseListCommand('shell   ')).toEqual({ type: 'invalid-shell' });
    expect(parseListCommand('')).toEqual({ type: 'empty' });
    expect(parseListCommand('unknown')).toEqual({ type: 'unknown', raw: 'unknown' });
  });

  test('accepts only y/yes confirmation responses', () => {
    expect(isAffirmativeResponse('Y')).toBe(true);
    expect(isAffirmativeResponse(' yes ')).toBe(true);
    expect(isAffirmativeResponse('n')).toBe(false);
    expect(isAffirmativeResponse('')).toBe(false);
  });
});
