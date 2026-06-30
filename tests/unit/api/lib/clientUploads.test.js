'use strict';

function loadClientUploads({ models, sequelize } = {}) {
  jest.resetModules();
  const getModels = jest.fn(() => models);
  const getSequelize = jest.fn(() => sequelize);
  jest.doMock('../../../../api/lib/db/index', () => ({ getModels, getSequelize }));
  return require('../../../../api/lib/db/clientUploads');
}

describe('clientUploads', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('listUploadTypesForUser returns [] when the username resolves to no user', async () => {
    const models = { User: { findOne: jest.fn().mockResolvedValue(null) } };
    const lib = loadClientUploads({ models });
    await expect(lib.listUploadTypesForUser('ghost')).resolves.toEqual([]);
  });

  test('listUploadTypesForUser groups uploads by type for the resolved user', async () => {
    const Upload = {
      findAll: jest.fn().mockResolvedValue([
        { uploadType: 'dmesg', count: '4' },
        { uploadType: 'netstat', count: '1' },
      ]),
    };
    const models = { User: { findOne: jest.fn().mockResolvedValue({ id: 7 }) }, Upload };
    const sequelize = { fn: jest.fn(() => 'COUNT_FN'), col: jest.fn(() => 'id') };
    const lib = loadClientUploads({ models, sequelize });

    await expect(lib.listUploadTypesForUser('alice')).resolves.toEqual([
      { uploadType: 'dmesg', count: 4 },
      { uploadType: 'netstat', count: 1 },
    ]);
    const callArg = Upload.findAll.mock.calls[0][0];
    expect(callArg.where).toEqual({ userId: 7 });
    expect(callArg.group).toEqual(['uploadType']);
  });

  test('listUploadsForUser scopes to the user and maps Device mac', async () => {
    const Upload = {
      findAll: jest.fn().mockResolvedValue([
        {
          id: 12,
          uploadType: 'dmesg',
          contentType: 'text/plain',
          srcIp: '10.0.0.1',
          apiTimestamp: 'ts',
          requestFilePath: null,
          localArtifactPath: '/data/x',
          isSymlink: false,
          symlinkPath: null,
          payloadSha256: 'sha',
          payloadBytes: 11,
          Device: { macAddress: 'aa:bb:cc:dd:ee:ff' },
        },
      ]),
    };
    const Device = { name: 'Device' };
    const models = { User: { findOne: jest.fn().mockResolvedValue({ id: 7 }) }, Upload, Device };
    const lib = loadClientUploads({ models });

    const rows = await lib.listUploadsForUser('dmesg', 'alice', { limit: 10, offset: 0 });

    expect(Upload.findAll.mock.calls[0][0].where).toEqual({ userId: 7, uploadType: 'dmesg' });
    expect(rows).toEqual([
      expect.objectContaining({ id: '12', macAddress: 'aa:bb:cc:dd:ee:ff', payloadBytes: 11 }),
    ]);
  });

  test('getUploadForUser returns null when not found for the user', async () => {
    const Upload = { findOne: jest.fn().mockResolvedValue(null) };
    const models = { User: { findOne: jest.fn().mockResolvedValue({ id: 7 }) }, Upload, Device: {} };
    const lib = loadClientUploads({ models });
    await expect(lib.getUploadForUser('dmesg', '12', 'alice')).resolves.toBeNull();
  });

  test('getUploadForUser includes payloadBinary only when requested', async () => {
    const row = {
      id: 12,
      uploadType: 'file',
      contentType: 'application/octet-stream',
      srcIp: null,
      apiTimestamp: 'ts',
      requestFilePath: null,
      localArtifactPath: null,
      isSymlink: false,
      symlinkPath: null,
      payloadSha256: 'sha',
      payloadBytes: 3,
      payloadText: null,
      payloadJson: null,
      payloadBinary: Buffer.from([9, 9, 9]),
      Device: { macAddress: 'aa:bb:cc:dd:ee:ff' },
    };
    const Upload = { findOne: jest.fn().mockResolvedValue(row) };
    const models = { User: { findOne: jest.fn().mockResolvedValue({ id: 7 }) }, Upload, Device: {} };
    const lib = loadClientUploads({ models });

    const withoutBinary = await lib.getUploadForUser('file', '12', 'alice');
    expect(withoutBinary).not.toHaveProperty('payloadBinary');
    expect(Upload.findOne.mock.calls[0][0].attributes).not.toContain('payloadBinary');

    const withBinary = await lib.getUploadForUser('file', '12', 'alice', { includeBinary: true });
    expect(withBinary.payloadBinary).toEqual(Buffer.from([9, 9, 9]));
    expect(Upload.findOne.mock.calls[1][0].attributes).toContain('payloadBinary');
  });
});
