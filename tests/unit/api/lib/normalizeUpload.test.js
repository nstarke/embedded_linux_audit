'use strict';

const { normalizeUpload } = require('../../../../api/lib/db/normalizeUpload');

describe('normalizeUpload', () => {
  test('normalizes arch json payloads', () => {
    const normalized = normalizeUpload({
      uploadType: 'arch',
      contentType: 'application/json',
      payloadText: '{"record":"arch","subcommand":"isa","value":"x86_64"}',
    });

    expect(normalized.archReport).toEqual({
      subcommand: 'isa',
      value: 'x86_64',
    });
  });

  test('normalizes grep text payloads', () => {
    const normalized = normalizeUpload({
      uploadType: 'grep',
      contentType: 'text/plain',
      requestFilePath: '/etc',
      payloadText: '/etc/passwd:1:root\n/etc/group:2:daemon',
    });

    expect(normalized.grepMatches).toHaveLength(2);
    expect(normalized.grepMatches[0]).toEqual({
      recordIndex: 0,
      rootPath: '/etc',
      filePath: '/etc/passwd',
      lineNumber: 1,
      lineText: 'root',
    });
  });
});
