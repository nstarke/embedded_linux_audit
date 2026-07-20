'use strict';

const { getModels, getSequelize } = require('./index');
const { normalizeMac } = require('./deviceRegistry');

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
//
// An optional `mac` narrows the result to the single associated device with
// that MAC (canonicalized, so any separator style matches). The filter stays
// within the user's own devices, so a MAC the user is not associated with (or
// an unknown one) yields [] — no cross-user leakage and no enumeration.
async function resolveUserDeviceIds(username, { mac = null } = {}) {
  const userId = await resolveUserId(username);
  if (userId === null) {
    return [];
  }
  const { UserDevice, Device } = getModels();
  const query = { where: { userId }, attributes: ['deviceId'] };
  if (mac) {
    query.include = [{
      model: Device,
      attributes: [],
      where: { macAddress: normalizeMac(mac) },
      required: true,
    }];
  }
  const links = await UserDevice.findAll(query);
  return links.map((l) => l.deviceId);
}

function metadataFromUpload(upload) {
  return {
    // Sequelize hands BIGINT back as a string; the client API contract is a
    // JSON number. Exact up to 2^53-1, far beyond any realistic artifact count.
    id: Number(upload.id),
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

async function listUploadTypesForUser(username, { mac = null } = {}) {
  const deviceIds = await resolveUserDeviceIds(username, { mac });
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

async function listUploadsForUser(uploadType, username, { limit = 100, offset = 0, mac = null } = {}) {
  const deviceIds = await resolveUserDeviceIds(username, { mac });
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

// Upload ids are globally unique, so a record is addressable by id alone; the
// device-association filter is what scopes visibility.
async function getUploadForUser(id, username, { includeBinary = false } = {}) {
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
    where: { id, deviceId: deviceIds },
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
