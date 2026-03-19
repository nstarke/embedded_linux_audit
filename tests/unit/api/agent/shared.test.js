'use strict';

const {
  listBinaryEntries,
  isSafeSinglePathSegment,
  isSafeRelativePath,
} = require('../../../../api/agent/routes/shared');

function fileEntry(name) {
  return {
    name,
    isFile: () => true,
  };
}

function dirEntry(name) {
  return {
    name,
    isFile: () => false,
  };
}

describe('agent route shared helpers', () => {
  test('listBinaryEntries filters state files, derives ISA names, and sorts output', async () => {
    const fsp = {
      readdir: jest.fn().mockResolvedValue([
        fileEntry('.release_state.json'),
        fileEntry('.release_state.20260319'),
        fileEntry('embedded_linux_audit-arm32-be'),
        fileEntry('ela-x86_64'),
        fileEntry('plain-name'),
        dirEntry('nested'),
      ]),
    };

    await expect(listBinaryEntries('/assets', fsp, '.release_state.json')).resolves.toEqual([
      { isa: 'arm32-be', fileName: 'embedded_linux_audit-arm32-be', url: '/isa/arm32-be' },
      { isa: 'plain-name', fileName: 'plain-name', url: '/isa/plain-name' },
      { isa: 'x86_64', fileName: 'ela-x86_64', url: '/isa/x86_64' },
    ]);
  });

  test('listBinaryEntries falls back to an empty list on readdir failure', async () => {
    const fsp = {
      readdir: jest.fn().mockRejectedValue(new Error('missing')),
    };

    await expect(listBinaryEntries('/assets', fsp, '.release_state.json')).resolves.toEqual([]);
  });

  test('isSafeSinglePathSegment accepts plain names and rejects traversal or separators', () => {
    expect(isSafeSinglePathSegment('script.ela')).toBe(true);
    expect(isSafeSinglePathSegment('')).toBe(false);
    expect(isSafeSinglePathSegment('.')).toBe(false);
    expect(isSafeSinglePathSegment('..')).toBe(false);
    expect(isSafeSinglePathSegment('a/../b')).toBe(false);
    expect(isSafeSinglePathSegment('a\\b')).toBe(false);
    expect(isSafeSinglePathSegment('bad..name')).toBe(false);
  });

  test('isSafeRelativePath accepts nested safe paths and rejects invalid segments', () => {
    expect(isSafeRelativePath('nested/test.ela')).toBe(true);
    expect(isSafeRelativePath('nested/deeper/test.sh')).toBe(true);
    expect(isSafeRelativePath('')).toBe(false);
    expect(isSafeRelativePath('../escape.sh')).toBe(false);
    expect(isSafeRelativePath('nested/..')).toBe(false);
    expect(isSafeRelativePath('nested\\bad')).toBe(false);
  });
});
