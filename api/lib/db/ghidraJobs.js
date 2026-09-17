// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { getModels } = require('./index');
const { resolveUserId, resolveUserDeviceIds } = require('./deviceRegistry');

/*
 * DB helpers for Ghidra decompilation jobs. Creation and read-back run in the
 * client API (user-scoped, same device-association ACL as clientUploads /
 * moduleBuilds); status transitions and progress counters are written by the
 * ghidra-analysis worker (api/ghidra/worker.js).
 *
 * Status machine: queued -> copying -> analyzing -> succeeded | failed.
 */

async function createGhidraJob({ deviceId, username }) {
  const userId = await resolveUserId(username);
  const { GhidraAnalysisJob } = getModels();
  return GhidraAnalysisJob.create({
    deviceId,
    userId,
    status: 'queued',
  });
}

// List jobs visible to `username` (their associated devices only), newest
// first. Optional mac narrows to one device.
async function listGhidraJobs(username, { mac = null, limit = 100 } = {}) {
  const deviceIds = await resolveUserDeviceIds(username, { mac });
  if (!deviceIds.length) {
    return [];
  }
  const { GhidraAnalysisJob } = getModels();
  return GhidraAnalysisJob.findAll({
    where: { deviceId: deviceIds },
    order: [['id', 'DESC']],
    limit,
  });
}

// One job by id, scoped to the caller's devices. Returns null when the job does
// not exist OR belongs to a device the caller is not associated with (the two
// are deliberately indistinguishable).
async function getGhidraJob(username, id) {
  const deviceIds = await resolveUserDeviceIds(username);
  if (!deviceIds.length) {
    return null;
  }
  const { GhidraAnalysisJob } = getModels();
  return GhidraAnalysisJob.findOne({
    where: { id, deviceId: deviceIds },
  });
}

/* ------------------------------------------------------------------------
 * Worker-side transitions. Each is a single targeted update by primary key.
 * ---------------------------------------------------------------------- */

async function markCopying(jobId) {
  const { GhidraAnalysisJob } = getModels();
  await GhidraAnalysisJob.update(
    { status: 'copying' },
    { where: { id: jobId } },
  );
}

// Enter the analyzing phase once the remote-copy landed and the fs root is
// known. filesFound is the ELF count the worker will decompile.
async function markAnalyzing(jobId, { fsRoot, outputRoot, filesFound }) {
  const { GhidraAnalysisJob } = getModels();
  await GhidraAnalysisJob.update({
    status: 'analyzing',
    fsRoot: fsRoot || null,
    outputRoot: outputRoot || null,
    filesFound: Number.isInteger(filesFound) ? filesFound : 0,
    filesAnalyzed: 0,
  }, { where: { id: jobId } });
}

// Progress heartbeat during the analyzing phase (how many ELFs are decompiled
// so far), so GET /ghidra-analysis/:id reflects a running job.
async function updateAnalyzedCount(jobId, filesAnalyzed) {
  const { GhidraAnalysisJob } = getModels();
  await GhidraAnalysisJob.update(
    { filesAnalyzed: Number.isInteger(filesAnalyzed) ? filesAnalyzed : 0 },
    { where: { id: jobId } },
  );
}

async function markSucceeded(jobId, { filesFound, filesAnalyzed, outputRoot } = {}) {
  const { GhidraAnalysisJob } = getModels();
  const patch = { status: 'succeeded', errorMessage: null };
  if (Number.isInteger(filesFound)) patch.filesFound = filesFound;
  if (Number.isInteger(filesAnalyzed)) patch.filesAnalyzed = filesAnalyzed;
  if (outputRoot) patch.outputRoot = outputRoot;
  await GhidraAnalysisJob.update(patch, { where: { id: jobId } });
}

async function markFailed(jobId, errorMessage) {
  const { GhidraAnalysisJob } = getModels();
  await GhidraAnalysisJob.update({
    status: 'failed',
    errorMessage: String(errorMessage || 'unknown error').slice(0, 4000),
  }, { where: { id: jobId } });
}

// Resolve the on-disk filesystem root the agent uploaded to for `deviceId`, by
// reading back the most recent 'file' upload's stored artifact path. The upload
// handler writes every remote-copied file under <data>/<macDir>/fs/<abs path>,
// where <macDir> is the agent's egress-NIC MAC as it appeared in the upload URL
// (which is NOT necessarily the DB's normalized MAC — hence resolving it from a
// real artifact path rather than reconstructing it). Returns the absolute
// <data>/<macDir>/fs path, or null when the device has no file uploads yet.
async function latestFilesystemUploadPath(deviceId) {
  const { Upload } = getModels();
  const upload = await Upload.findOne({
    where: { deviceId, uploadType: 'file' },
    order: [['id', 'DESC']],
  });
  return upload && upload.localArtifactPath ? upload.localArtifactPath : null;
}

module.exports = {
  resolveUserId,
  resolveUserDeviceIds,
  createGhidraJob,
  listGhidraJobs,
  getGhidraJob,
  markCopying,
  markAnalyzing,
  updateAnalyzedCount,
  markSucceeded,
  markFailed,
  latestFilesystemUploadPath,
};
