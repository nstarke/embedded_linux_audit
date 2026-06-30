'use strict';

const { getModels, getSequelize } = require('./index');

/*
 * Read-side queries for the client API.  Visibility is scoped by device
 * association: a user sees an artifact only when its device has been associated
 * with that user (recorded when the user's agent phones into the terminal API;
 * see associateUserDevice in deviceRegistry). A user with no associated devices
 * sees nothing.
 */

const METADATA_ATTRIBUTES = [
  'id',
  'uploadType',
  'contentType',
  'srcIp',
  'apiTimestamp',
  'requestFilePath',
  'localArtifactPath',
  'isSymlink',
  'symlinkPath',
  'payloadSha256',
  'payloadBytes',
];

async function resolveUserId(username) {
  if (!username) {
    return null;
  }
  const { User } = getModels();
  const user = await User.findOne({ where: { username } });
  return user ? user.id : null;
}

// Device ids associated with the user (via the terminal phone-home). Returns []
// when there is no such user or the user has not associated any devices.
async function resolveUserDeviceIds(username) {
  const userId = await resolveUserId(username);
  if (userId === null) {
    return [];
  }
  const { UserDevice } = getModels();
  const links = await UserDevice.findAll({ where: { userId }, attributes: ['deviceId'] });
  return links.map((l) => l.deviceId);
}

function metadataFromUpload(upload) {
  return {
    id: String(upload.id),
    uploadType: upload.uploadType,
    contentType: upload.contentType,
    macAddress: upload.Device ? upload.Device.macAddress : null,
    srcIp: upload.srcIp,
    apiTimestamp: upload.apiTimestamp,
    requestFilePath: upload.requestFilePath,
    localArtifactPath: upload.localArtifactPath,
    isSymlink: upload.isSymlink,
    symlinkPath: upload.symlinkPath,
    payloadSha256: upload.payloadSha256,
    payloadBytes: upload.payloadBytes,
  };
}

async function listUploadTypesForUser(username) {
  const deviceIds = await resolveUserDeviceIds(username);
  if (deviceIds.length === 0) {
    return [];
  }
  const sequelize = getSequelize();
  const { Upload } = getModels();
  const rows = await Upload.findAll({
    attributes: ['uploadType', [sequelize.fn('COUNT', sequelize.col('id')), 'count']],
    where: { deviceId: deviceIds },
    group: ['uploadType'],
    order: [['uploadType', 'ASC']],
    raw: true,
  });
  return rows.map((row) => ({ uploadType: row.uploadType, count: Number(row.count) }));
}

async function listUploadsForUser(uploadType, username, { limit = 100, offset = 0 } = {}) {
  const deviceIds = await resolveUserDeviceIds(username);
  if (deviceIds.length === 0) {
    return [];
  }
  const { Upload, Device } = getModels();
  const rows = await Upload.findAll({
    attributes: METADATA_ATTRIBUTES,
    where: { deviceId: deviceIds, uploadType },
    include: [{ model: Device, attributes: ['macAddress'] }],
    order: [['apiTimestamp', 'DESC'], ['id', 'DESC']],
    limit,
    offset,
  });
  return rows.map(metadataFromUpload);
}

async function getUploadForUser(uploadType, id, username, { includeBinary = false } = {}) {
  const deviceIds = await resolveUserDeviceIds(username);
  if (deviceIds.length === 0) {
    return null;
  }
  const { Upload, Device } = getModels();
  const attributes = [...METADATA_ATTRIBUTES, 'payloadText', 'payloadJson'];
  if (includeBinary) {
    attributes.push('payloadBinary');
  }
  const upload = await Upload.findOne({
    where: { id, deviceId: deviceIds, uploadType },
    attributes,
    include: [{ model: Device, attributes: ['macAddress'] }],
  });
  if (!upload) {
    return null;
  }
  const result = {
    ...metadataFromUpload(upload),
    payloadText: upload.payloadText,
    payloadJson: upload.payloadJson,
  };
  if (includeBinary) {
    result.payloadBinary = upload.payloadBinary;
  }
  return result;
}

module.exports = {
  listUploadTypesForUser,
  listUploadsForUser,
  getUploadForUser,
};
