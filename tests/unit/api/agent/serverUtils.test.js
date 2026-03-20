'use strict';

const path = require('path');
const os = require('os');
const fs = require('fs/promises');
const {
  findProjectRoot,
  isValidMacAddress,
  normalizeContentType,
  logPathForContentType,
  augmentJsonPayload,
  resolveProjectPath,
  sanitizeUploadPath,
  isWithinRoot,
  selectStartupDataDir,
  getClientIp,
  writeUploadFile,
} = require('../../../../api/agent/serverUtils');

describe('agent server utils', () => {
  // findProjectRoot
  describe('findProjectRoot', () => {
    test('finds the project root from a nested directory', () => {
      const root = findProjectRoot(__dirname);
      // Confirm the returned directory contains the expected markers
      const syncFs = require('fs');
      expect(syncFs.existsSync(path.join(root, 'Makefile'))).toBe(true);
      expect(syncFs.existsSync(path.join(root, 'api', 'agent', 'package.json'))).toBe(true);
    });

    test('falls back to startDir/../.. when no markers are found', () => {
      const tmpDir = os.tmpdir();
      const result = findProjectRoot(tmpDir);
      expect(result).toBe(path.resolve(tmpDir, '..', '..'));
    });
  });

  // isValidMacAddress
  describe('isValidMacAddress', () => {
    test('accepts a valid lowercase MAC address', () => {
      expect(isValidMacAddress('aa:bb:cc:dd:ee:ff')).toBe(true);
    });

    test('accepts a valid uppercase MAC address', () => {
      expect(isValidMacAddress('AA:BB:CC:DD:EE:FF')).toBe(true);
    });

    test('accepts a mixed-case MAC address', () => {
      expect(isValidMacAddress('00:1A:2b:3C:4d:5E')).toBe(true);
    });

    test('rejects a MAC address with hyphens', () => {
      expect(isValidMacAddress('aa-bb-cc-dd-ee-ff')).toBe(false);
    });

    test('rejects a MAC address that is too short', () => {
      expect(isValidMacAddress('aa:bb:cc:dd:ee')).toBe(false);
    });

    test('rejects null', () => {
      expect(isValidMacAddress(null)).toBe(false);
    });

    test('rejects undefined', () => {
      expect(isValidMacAddress(undefined)).toBe(false);
    });

    test('rejects an empty string', () => {
      expect(isValidMacAddress('')).toBe(false);
    });
  });

  // normalizeContentType
  describe('normalizeContentType', () => {
    test('strips parameters', () => {
      expect(normalizeContentType('application/json; charset=utf-8')).toBe('application/json');
    });

    test('lowercases the type', () => {
      expect(normalizeContentType('Application/JSON')).toBe('application/json');
    });

    test('handles a value with no parameters', () => {
      expect(normalizeContentType('text/plain')).toBe('text/plain');
    });

    test('returns empty string for missing header', () => {
      expect(normalizeContentType()).toBe('');
    });
  });

  // logPathForContentType
  describe('logPathForContentType', () => {
    const validTypes = {
      'application/json': 'json',
      'text/plain': 'txt',
    };

    test('returns the correct log path for a known content type', () => {
      const result = logPathForContentType('/data/logs/prefix', 'application/json', validTypes);
      expect(result).toBe('/data/logs/prefix.json.log');
    });

    test('uses "unknown" suffix for an unrecognised content type', () => {
      const result = logPathForContentType('/data/logs/prefix', 'application/octet-stream', validTypes);
      expect(result).toBe('/data/logs/prefix.unknown.log');
    });

    test('strips content-type parameters before matching', () => {
      const result = logPathForContentType('/data/logs/prefix', 'application/json; charset=utf-8', validTypes);
      expect(result).toBe('/data/logs/prefix.json.log');
    });
  });

  // augmentJsonPayload
  describe('augmentJsonPayload', () => {
    test('enriches a single-object payload', () => {
      const enriched = augmentJsonPayload(Buffer.from('{"x":1}\n'), '2026-03-17T10:00:00.000Z', '10.0.0.1');
      expect(enriched.toString('utf8')).toContain('"api_timestamp":"2026-03-17T10:00:00.000Z"');
      expect(enriched.toString('utf8')).toContain('"src_ip":"10.0.0.1"');
    });

    test('enriches each line of an NDJSON payload', () => {
      const ndjson = '{"a":1}\n{"b":2}\n';
      const enriched = augmentJsonPayload(Buffer.from(ndjson), 'ts', '1.2.3.4');
      const lines = enriched.toString('utf8').trim().split('\n');
      expect(lines).toHaveLength(2);
      const first = JSON.parse(lines[0]);
      const second = JSON.parse(lines[1]);
      expect(first).toMatchObject({ a: 1, api_timestamp: 'ts', src_ip: '1.2.3.4' });
      expect(second).toMatchObject({ b: 2, api_timestamp: 'ts', src_ip: '1.2.3.4' });
    });

    test('returns the original buffer when the payload is empty', () => {
      const buf = Buffer.from('   ');
      expect(augmentJsonPayload(buf, 'ts', 'ip')).toBe(buf);
    });

    test('returns the original buffer when the single JSON value is not an object', () => {
      const buf = Buffer.from('[1,2,3]');
      expect(augmentJsonPayload(buf, 'ts', 'ip')).toBe(buf);
    });

    test('returns the original buffer when the single JSON value is null', () => {
      const buf = Buffer.from('null');
      expect(augmentJsonPayload(buf, 'ts', 'ip')).toBe(buf);
    });

    test('returns the original buffer when an NDJSON line is not an object', () => {
      const buf = Buffer.from('{"a":1}\n[1,2]\n');
      expect(augmentJsonPayload(buf, 'ts', 'ip')).toBe(buf);
    });
  });

  // resolveProjectPath
  describe('resolveProjectPath', () => {
    test('returns an absolute path unchanged', () => {
      expect(resolveProjectPath('/some/root', '/etc/hosts')).toBe('/etc/hosts');
    });

    test('resolves a relative path against the project root', () => {
      expect(resolveProjectPath('/some/root', 'data/file.txt')).toBe('/some/root/data/file.txt');
    });
  });

  // isWithinRoot
  describe('isWithinRoot', () => {
    test('returns true for a nested path', () => {
      const root = '/tmp/root';
      expect(isWithinRoot(path.join(root, 'a', 'b'), root)).toBe(true);
    });

    test('returns true for the root itself', () => {
      expect(isWithinRoot('/tmp/root', '/tmp/root')).toBe(true);
    });

    test('returns false for a path outside the root', () => {
      expect(isWithinRoot('/tmp/other', '/tmp/root')).toBe(false);
    });

    test('returns false for a path that shares a prefix but is not a child', () => {
      expect(isWithinRoot('/tmp/rootsibling', '/tmp/root')).toBe(false);
    });
  });

  // getClientIp
  describe('getClientIp', () => {
    test('returns req.ip when present', () => {
      expect(getClientIp({ ip: '10.0.0.1' })).toBe('10.0.0.1');
    });

    test('strips IPv4-mapped IPv6 prefix from req.ip', () => {
      expect(getClientIp({ ip: '::ffff:192.168.1.1' })).toBe('192.168.1.1');
    });

    test('falls back to socket.remoteAddress when req.ip is absent', () => {
      expect(getClientIp({ socket: { remoteAddress: '10.0.0.2' } })).toBe('10.0.0.2');
    });

    test('strips IPv4-mapped prefix from socket.remoteAddress', () => {
      expect(getClientIp({ socket: { remoteAddress: '::ffff:172.16.0.1' } })).toBe('172.16.0.1');
    });

    test('returns an empty string when neither field is present', () => {
      expect(getClientIp({})).toBe('');
    });
  });

  // sanitizeUploadPath
  describe('sanitizeUploadPath', () => {
    test('rejects path traversal with leading double-dot', () => {
      expect(sanitizeUploadPath('../../etc/passwd')).toBeNull();
    });

    test('accepts a path where normalization removes embedded traversal', () => {
      expect(sanitizeUploadPath('/etc/../passwd')).toBe('passwd');
    });

    test('rejects null', () => {
      expect(sanitizeUploadPath(null)).toBeNull();
    });

    test('rejects a non-string value', () => {
      expect(sanitizeUploadPath(42)).toBeNull();
    });

    test('rejects an empty string', () => {
      expect(sanitizeUploadPath('')).toBeNull();
    });

    test('rejects a bare dot', () => {
      expect(sanitizeUploadPath('.')).toBeNull();
    });

    test('converts backslashes and accepts the result', () => {
      expect(sanitizeUploadPath('sub\\file.txt')).toBe('sub/file.txt');
    });

    test('accepts a normal relative path', () => {
      expect(sanitizeUploadPath('logs/output.log')).toBe('logs/output.log');
    });
  });

  // selectStartupDataDir
  describe('selectStartupDataDir', () => {
    test('creates a fresh timestamp path by default', async () => {
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

    test('reuses the highest numeric timestamp directory', async () => {
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

    test('falls back to current timestamp when no prior timestamp exists', async () => {
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

    test('falls back to current timestamp when the data root does not exist', async () => {
      const root = path.join(os.tmpdir(), `ela-nonexistent-${Date.now()}`);

      const selected = await selectStartupDataDir(root, {
        reuseLastTimestampDir: true,
        now: () => 99999,
      });

      expect(selected).toEqual({
        dataDir: path.join(root, '99999'),
        timestamp: '99999',
        reusedExisting: false,
      });
    });
  });

  // writeUploadFile
  describe('writeUploadFile', () => {
    test('writes a file to the expected destination', async () => {
      const baseDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ela-upload-'));
      const payload = Buffer.from('hello');

      const dest = await writeUploadFile(baseDir, 'sub/file.txt', payload);

      expect(dest).toBe(path.join(baseDir, 'sub', 'file.txt'));
      const contents = await fs.readFile(dest);
      expect(contents).toEqual(payload);
    });

    test('creates intermediate directories', async () => {
      const baseDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ela-upload-'));

      await writeUploadFile(baseDir, 'a/b/c/file.txt', Buffer.from('x'));

      const stat = await fs.stat(path.join(baseDir, 'a', 'b', 'c', 'file.txt'));
      expect(stat.isFile()).toBe(true);
    });

    test('throws for a path that escapes the base directory', async () => {
      const baseDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ela-upload-'));

      await expect(writeUploadFile(baseDir, '../escape.txt', Buffer.from('x'))).rejects.toThrow('invalid path');
    });
  });
});
