'use strict';

const {
  isAffirmativeResponse,
  parseListCommand,
} = require('../../../../api/terminal/listCommands');

describe('terminal list command helpers', () => {
  test('parses update, shell, cmd, and set batch commands', () => {
    expect(parseListCommand('update')).toEqual({ type: 'update' });
    expect(parseListCommand('shell uname -a')).toEqual({
      type: 'shell-all',
      command: 'uname -a',
    });
    expect(parseListCommand('cmd linux uname -a')).toEqual({
      type: 'cmd-all',
      command: 'linux uname -a',
    });
    expect(parseListCommand('set ELA_API_URL https://ela.example.com/upload')).toEqual({
      type: 'set-all',
      key: 'ELA_API_URL',
      value: 'https://ela.example.com/upload',
    });
    expect(parseListCommand('shell   ')).toEqual({ type: 'invalid-shell' });
    expect(parseListCommand('cmd')).toEqual({ type: 'invalid-cmd' });
    expect(parseListCommand('cmd   ')).toEqual({ type: 'invalid-cmd' });
    expect(parseListCommand('set')).toEqual({ type: 'invalid-set' });
    expect(parseListCommand('set ELA_API_URL')).toEqual({ type: 'invalid-set' });
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
