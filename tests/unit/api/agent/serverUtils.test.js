'use strict';

const path = require('path');
const os = require('os');
const fs = require('fs/promises');
const {
  normalizeContentType,
  augmentJsonPayload,
  sanitizeUploadPath,
  isWithinRoot,
  selectStartupDataDir,
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

  test('selectStartupDataDir creates a fresh timestamp path by default', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ela-agent-data-'));

    const selected = await selectStartupDataDir(root, {
      now: () => 12345,
    });

    expect(selected).toEqual({
      dataDir: path.join(root, '12345'),
      timestamp: '12345',
      reusedExisting: false,
    });
  });

  test('selectStartupDataDir reuses the highest numeric timestamp directory', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ela-agent-data-'));
    await fs.mkdir(path.join(root, '100'));
    await fs.mkdir(path.join(root, '999'));
    await fs.mkdir(path.join(root, 'release_binaries'));
    await fs.writeFile(path.join(root, 'note.txt'), 'x', 'utf8');

    const selected = await selectStartupDataDir(root, {
      reuseLastTimestampDir: true,
      now: () => 12345,
    });

    expect(selected).toEqual({
      dataDir: path.join(root, '999'),
      timestamp: '999',
      reusedExisting: true,
    });
  });

  test('selectStartupDataDir falls back to current timestamp when no prior timestamp exists', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ela-agent-data-'));
    await fs.mkdir(path.join(root, 'release_binaries'));

    const selected = await selectStartupDataDir(root, {
      reuseLastTimestampDir: true,
      now: () => 54321,
    });

    expect(selected).toEqual({
      dataDir: path.join(root, '54321'),
      timestamp: '54321',
      reusedExisting: false,
    });
  });
});
