'use strict';

const { parseCidr, isBlocked } = require('../../../../api/terminal/cidrUtil');

describe('parseCidr', () => {
  test('parses a bare IPv4 address as a /32', () => {
    const result = parseCidr('10.0.0.1');
    expect(result).not.toBeNull();
    expect(result.cidr).toBe('10.0.0.1/32');
  });

  test('parses a CIDR range', () => {
    const result = parseCidr('192.168.1.0/24');
    expect(result).not.toBeNull();
    expect(result.cidr).toBe('192.168.1.0/24');
  });

  test('parses a /0 (block all)', () => {
    const result = parseCidr('0.0.0.0/0');
    expect(result).not.toBeNull();
    expect(result.mask).toBe(0);
  });

  test('strips IPv6-mapped IPv4 prefix', () => {
    const result = parseCidr('::ffff:10.0.0.1');
    expect(result).not.toBeNull();
    expect(result.cidr).toBe('10.0.0.1/32');
  });

  test('returns null for a non-IP string', () => {
    expect(parseCidr('not-an-ip')).toBeNull();
  });

  test('returns null for an out-of-range octet', () => {
    expect(parseCidr('256.1.1.1')).toBeNull();
  });

  test('returns null for an invalid prefix', () => {
    expect(parseCidr('10.0.0.0/33')).toBeNull();
    expect(parseCidr('10.0.0.0/abc')).toBeNull();
  });

  test('returns null for empty input', () => {
    expect(parseCidr('')).toBeNull();
    expect(parseCidr(null)).toBeNull();
  });
});

describe('isBlocked', () => {
  test('returns true when IP matches a /32 entry', () => {
    const cidrs = [parseCidr('10.0.0.1')];
    expect(isBlocked('10.0.0.1', cidrs)).toBe(true);
  });

  test('returns true when IP falls within a CIDR range', () => {
    const cidrs = [parseCidr('192.168.1.0/24')];
    expect(isBlocked('192.168.1.50', cidrs)).toBe(true);
    expect(isBlocked('192.168.1.255', cidrs)).toBe(true);
  });

  test('returns false when IP is outside all CIDR ranges', () => {
    const cidrs = [parseCidr('192.168.1.0/24')];
    expect(isBlocked('192.168.2.1', cidrs)).toBe(false);
    expect(isBlocked('10.0.0.1', cidrs)).toBe(false);
  });

  test('handles IPv6-mapped IPv4 remote addresses', () => {
    const cidrs = [parseCidr('10.0.0.0/8')];
    expect(isBlocked('::ffff:10.0.0.5', cidrs)).toBe(true);
    expect(isBlocked('::ffff:192.168.1.1', cidrs)).toBe(false);
  });

  test('returns false for an empty block list', () => {
    expect(isBlocked('10.0.0.1', [])).toBe(false);
  });

  test('returns false for a null or empty remote address', () => {
    const cidrs = [parseCidr('10.0.0.0/8')];
    expect(isBlocked(null, cidrs)).toBe(false);
    expect(isBlocked('', cidrs)).toBe(false);
  });
});
