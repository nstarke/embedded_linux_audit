'use strict';

function loadClientUploads({ models, sequelize } = {}) {
  jest.resetModules();
  const getModels = jest.fn(() => models);
  const getSequelize = jest.fn(() => sequelize);
  jest.doMock('../../../../api/lib/db/index', () => ({ getModels, getSequelize }));
  return require('../../../../api/lib/db/clientUploads');
}

// Models with a user resolving to id 7 associated with devices [3, 5].
function modelsWithDevices(extra = {}) {
  return {
    User: { findOne: jest.fn().mockResolvedValue({ id: 7 }) },
    UserDevice: { findAll: jest.fn().mockResolvedValue([{ deviceId: 3 }, { deviceId: 5 }]) },
    ...extra,
  };
}

describe('clientUploads', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('returns [] when the username resolves to no user', async () => {
    const models = { User: { findOne: jest.fn().mockResolvedValue(null) } };
    const lib = loadClientUploads({ models });
    await expect(lib.listUploadTypesForUser('ghost')).resolves.toEqual([]);
  });

  test('returns [] when the user has no associated devices', async () => {
    const models = {
      User: { findOne: jest.fn().mockResolvedValue({ id: 7 }) },
      UserDevice: { findAll: jest.fn().mockResolvedValue([]) },
    };
    const lib = loadClientUploads({ models });
    await expect(lib.listUploadTypesForUser('alice')).resolves.toEqual([]);
  });

  test('listUploadTypesForUser groups uploads by type for the associated devices', async () => {
    const Upload = {
      findAll: jest.fn().mockResolvedValue([
        { uploadType: 'dmesg', count: '4' },
        { uploadType: 'netstat', count: '1' },
      ]),
    };
    const models = modelsWithDevices({ Upload });
    const sequelize = { fn: jest.fn(() => 'COUNT_FN'), col: jest.fn(() => 'id') };
    const lib = loadClientUploads({ models, sequelize });

    await expect(lib.listUploadTypesForUser('alice')).resolves.toEqual([
      { uploadType: 'dmesg', count: 4 },
      { uploadType: 'netstat', count: 1 },
    ]);
    const callArg = Upload.findAll.mock.calls[0][0];
    expect(callArg.where).toEqual({ deviceId: [3, 5] });
    expect(callArg.group).toEqual(['uploadType']);
    expect(models.UserDevice.findAll).toHaveBeenCalledWith({ where: { userId: 7 }, attributes: ['deviceId'] });
  });

  test('listUploadsForUser scopes to the associated devices and maps Device mac', async () => {
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
    const models = modelsWithDevices({ Upload, Device });
    const lib = loadClientUploads({ models });

    const rows = await lib.listUploadsForUser('dmesg', 'alice', { limit: 10, offset: 0 });

    expect(Upload.findAll.mock.calls[0][0].where).toEqual({ deviceId: [3, 5], uploadType: 'dmesg' });
    expect(rows).toEqual([
      expect.objectContaining({ id: '12', macAddress: 'aa:bb:cc:dd:ee:ff', payloadBytes: 11 }),
    ]);
  });

  test('getUploadForUser returns null when not found among associated devices', async () => {
    const Upload = { findOne: jest.fn().mockResolvedValue(null) };
    const models = modelsWithDevices({ Upload, Device: {} });
    const lib = loadClientUploads({ models });
    await expect(lib.getUploadForUser('dmesg', '12', 'alice')).resolves.toBeNull();
    expect(Upload.findOne.mock.calls[0][0].where).toEqual({ id: '12', deviceId: [3, 5], uploadType: 'dmesg' });
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
    const models = modelsWithDevices({ Upload, Device: {} });
    const lib = loadClientUploads({ models });

    const withoutBinary = await lib.getUploadForUser('file', '12', 'alice');
    expect(withoutBinary).not.toHaveProperty('payloadBinary');
    expect(Upload.findOne.mock.calls[0][0].attributes).not.toContain('payloadBinary');

    const withBinary = await lib.getUploadForUser('file', '12', 'alice', { includeBinary: true });
    expect(withBinary.payloadBinary).toEqual(Buffer.from([9, 9, 9]));
    expect(Upload.findOne.mock.calls[1][0].attributes).toContain('payloadBinary');
  });
});
