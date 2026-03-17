'use strict';

const path = require('path');
const {
  normalizeContentType,
  augmentJsonPayload,
  sanitizeUploadPath,
  isWithinRoot,
} = require('../../../../api/agent/serverUtils');

describe('agent server utils', () => {
  test('normalizeContentType strips parameters', () => {
    expect(normalizeContentType('application/json; charset=utf-8')).toBe('application/json');
  });

  test('augmentJsonPayload enriches single object payloads', () => {
    const enriched = augmentJsonPayload(Buffer.from('{"x":1}\n'), '2026-03-17T10:00:00.000Z', '10.0.0.1');
    expect(enriched.toString('utf8')).toContain('"api_timestamp":"2026-03-17T10:00:00.000Z"');
    expect(enriched.toString('utf8')).toContain('"src_ip":"10.0.0.1"');
  });

  test('sanitizeUploadPath rejects traversal', () => {
    expect(sanitizeUploadPath('../../etc/passwd')).toBeNull();
    expect(sanitizeUploadPath('/etc/../passwd')).toBe('passwd');
  });

  test('isWithinRoot validates nested paths', () => {
    const root = '/tmp/root';
    expect(isWithinRoot(path.join(root, 'a', 'b'), root)).toBe(true);
    expect(isWithinRoot('/tmp/other', root)).toBe(false);
  });
});
