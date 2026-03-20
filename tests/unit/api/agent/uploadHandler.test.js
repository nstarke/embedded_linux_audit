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

  // Input validation
  test('rejects an invalid MAC address', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'not-a-mac', type: 'cmd' },
      query: {},
      body: Buffer.from('hello'),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid mac address\n');
    expect(baseDeps.persistUpload).not.toHaveBeenCalled();
  });

  test('rejects symlink query arguments for non-file upload types', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'cmd' },
      query: { symlink: 'true' },
      body: Buffer.from('hello'),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('symlink arguments only allowed for /upload/file\n');
  });

  test('rejects an invalid symlink query value', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'file' },
      query: { symlink: 'maybe' },
      body: Buffer.from('hello'),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid symlink value\n');
  });

  test('rejects symlink=true when filePath or symlinkPath is missing', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'file' },
      query: { symlink: 'true' },
      body: Buffer.from('hello'),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('symlink uploads require filePath and symlinkPath\n');
  });

  test('rejects symlinkPath when symlink is not true', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'file' },
      query: { symlinkPath: '/target' },
      body: Buffer.from('hello'),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('symlinkPath requires symlink=true\n');
  });

  test('returns 415 for an unsupported content type', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'cmd' },
      query: {},
      body: Buffer.from('hello'),
      get: () => 'application/xml',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(415);
    expect(res.body).toContain('unsupported content type');
  });

  test('returns 415 when application/json is used for a type that does not allow it', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'log' },
      query: {},
      body: Buffer.from('{"x":1}'),
      get: () => 'application/json',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(415);
    expect(res.body).toContain('unsupported content type');
    expect(res.body).not.toContain('application/json');
  });

  test('treats a missing Content-Type as an unsupported type', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'cmd' },
      query: {},
      body: Buffer.from('hello'),
      get: () => null,
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(415);
  });

  test('falls back to an empty buffer when req.body is not a Buffer', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'cmd' },
      query: {},
      body: 'not-a-buffer',
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    expect(baseDeps.fsp.appendFile).toHaveBeenCalledWith(
      expect.any(String),
      // empty payload + '\n' = just a newline
      Buffer.from('\n'),
    );
  });

  // writeSymlink paths
  test('accepts a symlink upload and persists it with isSymlink=true', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'file' },
      query: { symlink: 'true', filePath: '/var/lib/link.sh', symlinkPath: '/target.sh' },
      body: Buffer.from(''),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    expect(baseDeps.fsp.symlink).toHaveBeenCalledWith('/target.sh', expect.stringContaining('var/lib/link.sh'));
    expect(baseDeps.persistUpload).toHaveBeenCalledWith(expect.objectContaining({
      isSymlink: true,
      symlinkPath: '/target.sh',
    }));
  });

  test('returns 400 when the symlink path escapes the base directory', async () => {
    const handler = createUploadHandler({ ...baseDeps, isWithinRoot: () => false });
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'file' },
      query: { symlink: 'true', filePath: '/etc/passwd', symlinkPath: '/target' },
      body: Buffer.from(''),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid symlink upload\n');
  });

  test('returns 400 when fsp.unlink throws a non-ENOENT error during symlink creation', async () => {
    const handler = createUploadHandler({
      ...baseDeps,
      fsp: {
        ...baseDeps.fsp,
        unlink: jest.fn().mockRejectedValue(Object.assign(new Error('permission denied'), { code: 'EACCES' })),
      },
    });
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'file' },
      query: { symlink: 'true', filePath: '/etc/passwd', symlinkPath: '/target' },
      body: Buffer.from(''),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid symlink upload\n');
  });

  test('returns 400 when writeUploadFile throws', async () => {
    const handler = createUploadHandler({
      ...baseDeps,
      writeUploadFile: jest.fn().mockRejectedValue(new Error('invalid path')),
    });
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'file' },
      query: { filePath: '/etc/passwd' },
      body: Buffer.from('data'),
      get: () => 'application/octet-stream',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body).toBe('invalid filePath\n');
  });

  test('still responds 200 when augmentJsonPayload throws', async () => {
    const handler = createUploadHandler({
      ...baseDeps,
      augmentJsonPayload: () => { throw new Error('bad json'); },
    });
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'arch' },
      query: {},
      body: Buffer.from('{"x":1}'),
      get: () => 'application/json',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    expect(baseDeps.persistUpload).toHaveBeenCalled();
  });

  // application/octet-stream for a log-style upload type
  test('writes a timestamped binary file for octet-stream uploads', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'log' },
      query: {},
      body: Buffer.from('\x00\x01\x02'),
      get: () => 'application/octet-stream',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    expect(baseDeps.fsp.writeFile).toHaveBeenCalledWith(
      expect.stringMatching(/upload_.*\.bin$/),
      expect.any(Buffer),
    );
    expect(baseDeps.persistUpload).toHaveBeenCalledWith(expect.objectContaining({
      contentType: 'application/octet-stream',
    }));
  });

  // Payload newline padding
  test('appends a newline to file-list payloads that do not end with one', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'file-list' },
      query: { filePath: '/var/log' },
      body: Buffer.from('no-newline'),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    const written = baseDeps.fsp.writeFile.mock.calls[0][1];
    expect(written[written.length - 1]).toBe(0x0a);
  });

  test('appends a newline to log payloads that do not end with one', async () => {
    const handler = createUploadHandler(baseDeps);
    const req = {
      params: { mac: 'aa:bb:cc:dd:ee:ff', type: 'cmd' },
      query: {},
      body: Buffer.from('no-newline'),
      get: () => 'text/plain',
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    const appended = baseDeps.fsp.appendFile.mock.calls[0][1];
    expect(appended[appended.length - 1]).toBe(0x0a);
  });
});
