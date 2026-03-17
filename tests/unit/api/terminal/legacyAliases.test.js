'use strict';

jest.mock('fs', () => ({
  readFileSync: jest.fn(),
}));

const fs = require('fs');
const { loadLegacyAliases } = require('../../../../api/terminal/legacyAliases');

describe('legacy alias loader', () => {
  test('returns parsed aliases when file exists', () => {
    fs.readFileSync.mockReturnValue('{"aa:bb":"router"}');
    expect(loadLegacyAliases('/tmp/file.json')).toEqual({ 'aa:bb': 'router' });
  });

  test('returns empty object when file is missing', () => {
    fs.readFileSync.mockImplementation(() => {
      throw new Error('missing');
    });
    expect(loadLegacyAliases('/tmp/file.json')).toEqual({});
  });
});
