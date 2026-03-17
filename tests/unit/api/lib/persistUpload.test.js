'use strict';

jest.mock('../../../../api/lib/db/index', () => ({
  getSequelize: jest.fn(),
  getModels: jest.fn(),
}));

jest.mock('../../../../api/lib/db/deviceRegistry', () => ({
  ensureDevice: jest.fn(),
}));

const { getSequelize, getModels } = require('../../../../api/lib/db/index');
const { ensureDevice } = require('../../../../api/lib/db/deviceRegistry');
const { persistUpload } = require('../../../../api/lib/db/persistUpload');

describe('persistUpload', () => {
  test('stores the local artifact path on the upload row', async () => {
    const createdUpload = { id: 42 };
    const transaction = {};
    const sequelize = {
      transaction: jest.fn(async (cb) => cb(transaction)),
    };
    const models = {
      Upload: {
        create: jest.fn().mockResolvedValue(createdUpload),
      },
      CommandUpload: { create: jest.fn() },
      ArchReport: { create: jest.fn() },
      FileListEntry: { bulkCreate: jest.fn() },
      GrepMatch: { bulkCreate: jest.fn() },
      SymlinkListEntry: { bulkCreate: jest.fn() },
      EfiVariable: { bulkCreate: jest.fn() },
      UbootEnvCandidate: { bulkCreate: jest.fn() },
      UbootEnvVariable: { bulkCreate: jest.fn() },
      LogEvent: { bulkCreate: jest.fn() },
    };

    getSequelize.mockReturnValue(sequelize);
    getModels.mockReturnValue(models);
    ensureDevice.mockResolvedValue({ id: 7 });

    const result = await persistUpload({
      macAddress: 'aa:bb:cc:dd:ee:ff',
      uploadType: 'file',
      contentType: 'application/octet-stream',
      apiTimestamp: '2026-03-17T10:00:00.000Z',
      requestFilePath: 'etc/passwd',
      localArtifactPath: '/var/lib/ela/data/123/aa:bb:cc:dd:ee:ff/fs/etc/passwd',
      payload: Buffer.from('abc'),
      payloadToPersist: Buffer.from('abc'),
    });

    expect(result).toBe(createdUpload);
    expect(models.Upload.create).toHaveBeenCalledWith(expect.objectContaining({
      requestFilePath: 'etc/passwd',
      localArtifactPath: '/var/lib/ela/data/123/aa:bb:cc:dd:ee:ff/fs/etc/passwd',
    }), { transaction });
  });
});
