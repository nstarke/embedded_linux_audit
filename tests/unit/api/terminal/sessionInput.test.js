'use strict';

const {
  PASSTHROUGH_EXIT_SEQUENCE,
  remoteInputForKeypress,
  shouldEnterPassthrough,
} = require('../../../../api/terminal/sessionInput');

describe('terminal session input helpers', () => {
  test('detects shell-like execute-command invocations for passthrough mode', () => {
    expect(shouldEnterPassthrough('linux execute-command sh')).toBe(true);
    expect(shouldEnterPassthrough('linux execute-command "/bin/sh"')).toBe(true);
    expect(shouldEnterPassthrough('linux execute-command busybox sh')).toBe(true);
    expect(shouldEnterPassthrough('linux execute-command exec bash')).toBe(true);
    expect(shouldEnterPassthrough('linux execute-command "uname -a"')).toBe(false);
    expect(shouldEnterPassthrough('linux dmesg')).toBe(false);
  });

  test('translates terminal keypresses into remote shell input', () => {
    expect(remoteInputForKeypress('a', 'a')).toBe('a');
    expect(remoteInputForKeypress('\r', 'return')).toBe('\n');
    expect(remoteInputForKeypress(null, 'up')).toBe('\x1b[A');
    expect(remoteInputForKeypress(null, 'backspace')).toBe('\x7f');
    expect(remoteInputForKeypress(PASSTHROUGH_EXIT_SEQUENCE, ']')).toBe(PASSTHROUGH_EXIT_SEQUENCE);
  });
});
