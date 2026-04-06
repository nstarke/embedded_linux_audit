'use strict';

const { parseCidr, isBlocked, isPrivateIp, resolveProxiedAddress } = require('../../../../api/terminal/cidrUtil');

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

describe('isPrivateIp', () => {
  test('returns true for 10.x.x.x', () => {
    expect(isPrivateIp('10.0.0.1')).toBe(true);
    expect(isPrivateIp('10.255.255.255')).toBe(true);
  });

  test('returns true for 172.16.x.x – 172.31.x.x', () => {
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('172.31.255.255')).toBe(true);
  });

  test('returns true for 192.168.x.x', () => {
    expect(isPrivateIp('192.168.0.1')).toBe(true);
  });

  test('returns true for loopback 127.x.x.x', () => {
    expect(isPrivateIp('127.0.0.1')).toBe(true);
  });

  test('returns true for IPv6 loopback ::1', () => {
    expect(isPrivateIp('::1')).toBe(true);
  });

  test('returns true for IPv6 unique-local fc00::/7', () => {
    expect(isPrivateIp('fc00::1')).toBe(true);
    expect(isPrivateIp('fd12:3456:789a::1')).toBe(true);
  });

  test('returns true for IPv6-mapped private IPv4', () => {
    expect(isPrivateIp('::ffff:192.168.1.1')).toBe(true);
  });

  test('returns false for public IPv4', () => {
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('203.0.113.1')).toBe(false);
  });

  test('returns false for null or empty input', () => {
    expect(isPrivateIp(null)).toBe(false);
    expect(isPrivateIp('')).toBe(false);
  });
});

describe('resolveProxiedAddress', () => {
  test('returns the socket address unchanged when it is public', () => {
    expect(resolveProxiedAddress('8.8.8.8', { 'x-forwarded-for': '1.2.3.4' })).toBe('8.8.8.8');
  });

  test('returns X-Forwarded-For first entry when socket address is private', () => {
    expect(resolveProxiedAddress('192.168.1.1', { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' })).toBe('1.2.3.4');
  });

  test('falls back to X-Real-IP when X-Forwarded-For is absent', () => {
    expect(resolveProxiedAddress('10.0.0.1', { 'x-real-ip': '9.9.9.9' })).toBe('9.9.9.9');
  });

  test('returns original private address when no proxy headers are present', () => {
    expect(resolveProxiedAddress('10.0.0.1', {})).toBe('10.0.0.1');
  });

  test('handles null remoteAddress', () => {
    expect(resolveProxiedAddress(null, { 'x-forwarded-for': '1.2.3.4' })).toBe(null);
  });

  test('handles null headers', () => {
    expect(resolveProxiedAddress('192.168.1.1', null)).toBe('192.168.1.1');
  });
});
