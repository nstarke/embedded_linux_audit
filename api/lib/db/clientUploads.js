'use strict';

const { getModels, getSequelize } = require('./index');

/*
 * Read-side queries for the client API.  Every query is scoped to a single
 * user (resolved from the client bearer token's username) so a client token
 * only ever sees artifacts uploaded by that same user's agent.  Uploads with a
 * null user_id (legacy or unauthenticated ingests) belong to no user and are
 * therefore invisible here.
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
  const userId = await resolveUserId(username);
  if (userId === null) {
    return [];
  }
  const sequelize = getSequelize();
  const { Upload } = getModels();
  const rows = await Upload.findAll({
    attributes: ['uploadType', [sequelize.fn('COUNT', sequelize.col('id')), 'count']],
    where: { userId },
    group: ['uploadType'],
    order: [['uploadType', 'ASC']],
    raw: true,
  });
  return rows.map((row) => ({ uploadType: row.uploadType, count: Number(row.count) }));
}

async function listUploadsForUser(uploadType, username, { limit = 100, offset = 0 } = {}) {
  const userId = await resolveUserId(username);
  if (userId === null) {
    return [];
  }
  const { Upload, Device } = getModels();
  const rows = await Upload.findAll({
    attributes: METADATA_ATTRIBUTES,
    where: { userId, uploadType },
    include: [{ model: Device, attributes: ['macAddress'] }],
    order: [['apiTimestamp', 'DESC'], ['id', 'DESC']],
    limit,
    offset,
  });
  return rows.map(metadataFromUpload);
}

async function getUploadForUser(uploadType, id, username, { includeBinary = false } = {}) {
  const userId = await resolveUserId(username);
  if (userId === null) {
    return null;
  }
  const { Upload, Device } = getModels();
  const attributes = [...METADATA_ATTRIBUTES, 'payloadText', 'payloadJson'];
  if (includeBinary) {
    attributes.push('payloadBinary');
  }
  const upload = await Upload.findOne({
    where: { id, userId, uploadType },
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
