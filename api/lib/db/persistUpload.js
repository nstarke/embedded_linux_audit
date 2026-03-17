'use strict';

const crypto = require('crypto');
const { getModels, getSequelize } = require('./index');
const { ensureDevice } = require('./deviceRegistry');
const { normalizeUpload } = require('./normalizeUpload');

function textPayloadForContentType(contentType, buffer) {
  if (!buffer || buffer.length === 0) {
    return null;
  }
  if (contentType === 'application/octet-stream') {
    return null;
  }
  return buffer.toString('utf8');
}

async function persistUpload(input) {
  const sequelize = getSequelize();
  const models = getModels();
  const payloadBuffer = Buffer.from(input.payload || Buffer.alloc(0));
  const payloadBytes = payloadBuffer.length;
  const payloadText = textPayloadForContentType(input.contentType, input.payloadToPersist);
  const normalized = normalizeUpload({
    uploadType: input.uploadType,
    contentType: input.contentType,
    requestFilePath: input.requestFilePath,
    payloadText,
  });

  return sequelize.transaction(async (transaction) => {
    const apiTimestamp = new Date(input.apiTimestamp);
    const device = await ensureDevice(input.macAddress, transaction, apiTimestamp);

    const upload = await models.Upload.create({
      deviceId: device.id,
      uploadType: input.uploadType,
      contentType: input.contentType,
      srcIp: input.srcIp || null,
      apiTimestamp,
      requestFilePath: input.requestFilePath || null,
      isSymlink: Boolean(input.isSymlink),
      symlinkPath: input.symlinkPath || null,
      payloadText: normalized.upload.payloadText,
      payloadJson: normalized.upload.payloadJson,
      payloadBinary: input.contentType === 'application/octet-stream' ? payloadBuffer : null,
      payloadSha256: crypto.createHash('sha256').update(payloadBuffer).digest('hex'),
      payloadBytes,
    }, { transaction });

    if (normalized.commandUpload) {
      await models.CommandUpload.create({
        uploadId: upload.id,
        ...normalized.commandUpload,
      }, { transaction });
    }

    if (normalized.archReport) {
      await models.ArchReport.create({
        uploadId: upload.id,
        ...normalized.archReport,
      }, { transaction });
    }

    const bulkInserts = [
      [models.FileListEntry, normalized.fileListEntries],
      [models.GrepMatch, normalized.grepMatches],
      [models.SymlinkListEntry, normalized.symlinkListEntries],
      [models.EfiVariable, normalized.efiVariables],
      [models.UbootEnvCandidate, normalized.ubootEnvCandidates],
      [models.UbootEnvVariable, normalized.ubootEnvVariables],
      [models.LogEvent, normalized.logEvents],
    ];

    for (const [model, rows] of bulkInserts) {
      if (!rows.length) {
        continue;
      }
      await model.bulkCreate(rows.map((row) => ({
        uploadId: upload.id,
        ...row,
      })), { transaction });
    }

    return upload;
  });
}

module.exports = {
  persistUpload,
};
