'use strict';

const { createUploadHandler } = require('../../../../api/agent/routes/uploadHandler');

function createRes() {
  return {
    statusCode: 200,
    headers: {},
    body: '',
    status(code) {
      this.statusCode = code;
      return this;
    },
    type(value) {
      this.headers['content-type'] = value;
      return this;
    },
    send(value) {
      this.body = value;
      return this;
    },
  };
}

describe('upload handler', () => {
  const baseDeps = {
    dataDir: '/data',
    path: require('path'),
    fsp: {
      mkdir: jest.fn().mockResolvedValue(undefined),
      appendFile: jest.fn().mockResolvedValue(undefined),
      writeFile: jest.fn().mockResolvedValue(undefined),
      unlink: jest.fn().mockRejectedValue(Object.assign(new Error('missing'), { code: 'ENOENT' })),
      symlink: jest.fn().mockResolvedValue(undefined),
    },
    crypto: { randomUUID: () => '12345678-1234-1234-1234-123456789abc' },
    validUploadTypes: new Set(['cmd', 'file', 'file-list', 'symlink-list', 'log', 'logs', 'arch', 'grep']),
    validContentTypes: {
      'text/plain': 'text_plain',
      'application/json': 'application_json',
      'application/octet-stream': 'application_octet_stream',
    },
    normalizeContentType: (value) => value.split(';', 1)[0].trim().toLowerCase(),
    sanitizeUploadPath: (value) => (value && !value.includes('..') ? value.replace(/^\/+/, '') : null),
    writeUploadFile: jest.fn().mockResolvedValue('/data/aa:bb:cc:dd:ee:ff/fs/etc/passwd'),
    augmentJsonPayload: (payload) => payload,
    logPathForContentType: (prefix) => `${prefix}.text_plain.log`,
    persistUpload: jest.fn().mockResolvedValue(undefined),
    isValidMacAddress: (value) => /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(value),
    verboseRequestLog: jest.fn(),
    verboseResponseLog: jest.fn(),
    getClientIp: () => '127.0.0.1',
    isWithinRoot: () => true,
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('rejects invalid upload type', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'bad' },
      query: {},
      body: Buffer.from('hello'),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('invalid upload type\n');
    expect(baseDeps.persistUpload).not.toHaveBeenCalled();
  });

  test('accepts arch json uploads and persists them', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'arch' },
      query: {},
      body: Buffer.from('{"record":"arch","subcommand":"isa","value":"x86_64"}\n'),
      get: () => 'application/json',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    expect(baseDeps.persistUpload).toHaveBeenCalledWith(expect.objectContaining({
      uploadType: 'arch',
      contentType: 'application/json',
      localArtifactPath: '/data/aa:bb:cc:dd:ee:ff/arch/arch.text_plain.log',
    }));
  });

  test('requires absolute filePath for grep uploads', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'grep' },
      query: { filePath: 'relative' },
      body: Buffer.from('/etc/passwd:1:root'),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('grep uploads require absolute filePath\n');
  });

  test('stores local file artifact path in persistence payload', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'file' },
      query: { filePath: '/etc/passwd' },
      body: Buffer.from('root:x:0:0:root:/root:/bin/sh\n'),
      get: () => 'application/octet-stream',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    expect(baseDeps.writeUploadFile).toHaveBeenCalledWith(
      '/data/aa:bb:cc:dd:ee:ff/fs',
      'etc/passwd',
      expect.any(Buffer),
    );
    expect(baseDeps.persistUpload).toHaveBeenCalledWith(expect.objectContaining({
      uploadType: 'file',
      localArtifactPath: '/data/aa:bb:cc:dd:ee:ff/fs/etc/passwd',
      requestFilePath: 'etc/passwd',
    }));
  });

  test('stores local list artifact path in persistence payload', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'grep' },
      query: { filePath: '/etc' },
      body: Buffer.from('/etc/passwd:1:root\n'),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    expect(baseDeps.persistUpload).toHaveBeenCalledWith(expect.objectContaining({
      uploadType: 'grep',
      localArtifactPath: expect.stringMatching(/^\/data\/aa:bb:cc:dd:ee:ff\/grep\/etc_[0-9T]+Z$/),
    }));
  });
});
