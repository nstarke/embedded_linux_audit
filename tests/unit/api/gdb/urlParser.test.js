'use strict';

const { parseGdbUrl, isValidHexKey } = require('../../../../api/gdb/urlParser');

const VALID_KEY = 'aabbccddeeff00112233445566778899';

describe('parseGdbUrl', () => {
  test('parses valid in URL', () => {
    expect(parseGdbUrl(`/gdb/in/${VALID_KEY}`))
      .toEqual({ direction: 'in', hexkey: VALID_KEY });
  });

  test('parses valid out URL', () => {
    expect(parseGdbUrl(`/gdb/out/${VALID_KEY}`))
      .toEqual({ direction: 'out', hexkey: VALID_KEY });
  });

  test('returns null for unrecognised path', () => {
    expect(parseGdbUrl('/other/path')).toBeNull();
  });

  test('returns null for uppercase hex in key', () => {
    expect(parseGdbUrl('/gdb/in/AABBCCDDEEFF00112233445566778899')).toBeNull();
  });

  test('returns null for key that is too short', () => {
    expect(parseGdbUrl('/gdb/in/aabb')).toBeNull();
  });

  test('returns null for key that is too long', () => {
    expect(parseGdbUrl(`/gdb/in/${VALID_KEY}0`)).toBeNull();
  });

  test('returns null for wrong direction token', () => {
    expect(parseGdbUrl(`/gdb/side/${VALID_KEY}`)).toBeNull();
  });

  test('returns null for null argument', () => {
    expect(parseGdbUrl(null)).toBeNull();
  });

  test('returns null for empty string', () => {
    expect(parseGdbUrl('')).toBeNull();
  });

  test('returns null for non-hex chars in key', () => {
    const bad = 'aabbccddeeff001122334455667788zz';
    expect(parseGdbUrl(`/gdb/in/${bad}`)).toBeNull();
  });
});

describe('isValidHexKey', () => {
  test('accepts valid 32-char lowercase hex', () => {
    expect(isValidHexKey(VALID_KEY)).toBe(true);
  });

  test('accepts all-zero key', () => {
    expect(isValidHexKey('00000000000000000000000000000000')).toBe(true);
  });

  test('accepts all-f key', () => {
    expect(isValidHexKey('ffffffffffffffffffffffffffffffff')).toBe(true);
  });

  test('rejects uppercase', () => {
    expect(isValidHexKey('AABBCCDDEEFF00112233445566778899')).toBe(false);
  });

  test('rejects too-short key', () => {
    expect(isValidHexKey('aabbccdd')).toBe(false);
  });

  test('rejects too-long key', () => {
    expect(isValidHexKey(`${VALID_KEY}0`)).toBe(false);
  });

  test('rejects non-hex chars', () => {
    expect(isValidHexKey('aabbccddeeff001122334455667788zz')).toBe(false);
  });

  test('rejects null', () => {
    expect(isValidHexKey(null)).toBe(false);
  });

  test('rejects empty string', () => {
    expect(isValidHexKey('')).toBe(false);
  });
});
