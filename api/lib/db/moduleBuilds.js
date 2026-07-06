// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const crypto = require('crypto');
const { Op } = require('sequelize');
const { getModels } = require('./index');
const { normalizeMac } = require('./deviceRegistry');

// A .ko grants ring-0 on the target, so download tokens are always single-use
// (consuming one clears its hash). Time-based expiry is opt-in: set
// ELA_MODULE_TOKEN_TTL_MINUTES to a positive integer to also expire unused
// tokens after that many minutes (useful to bound the window on a slow or
// hostile link). Unset / 0 / non-numeric => null => no time-based expiry, so a
// minted URL stays valid until it is used.
const DEFAULT_TOKEN_TTL_MS = (() => {
  const raw = process.env.ELA_MODULE_TOKEN_TTL_MINUTES;
  if (raw === undefined || raw === '') {
    return null;
  }
  const minutes = Number.parseInt(raw, 10);
  return Number.isInteger(minutes) && minutes > 0 ? minutes * 60 * 1000 : null;
})();

function hashToken(token) {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

/*
 * DB helpers for kernel-module build requests. Creation and read-back run in
 * the client API (user-scoped, same device-association ACL as clientUploads);
 * status transitions run in the builder worker.
 */

async function resolveUserId(username) {
  if (!username) {
    return null;
  }
  const { User } = getModels();
  const user = await User.findOne({ where: { username } });
  return user ? user.id : null;
}

// The latest module-buildinfo facts for a device, or null when the device has
// never uploaded buildinfo. Reads the normalized kernel_build_infos row joined
// through its upload for recency and the device scope.
async function latestBuildInfoForDevice(deviceId) {
  const { Upload, KernelBuildInfo } = getModels();
  const upload = await Upload.findOne({
    where: { deviceId, uploadType: 'module-buildinfo' },
    include: [{ model: KernelBuildInfo, required: true }],
    order: [['id', 'DESC']],
  });
  if (!upload || !upload.KernelBuildInfo) {
    return null;
  }
  return { upload, buildInfo: upload.KernelBuildInfo };
}

// The latest stored kernel-config artifact path for a device (uploaded by
// `linux modules buildinfo` right after the JSON), or null.
async function latestKernelConfigPath(deviceId) {
  const { Upload } = getModels();
  const upload = await Upload.findOne({
    where: { deviceId, uploadType: 'kernel-config' },
    order: [['id', 'DESC']],
  });
  return upload && upload.localArtifactPath ? upload.localArtifactPath : null;
}

// Create a build request row (status 'queued') from a device's latest
// buildinfo. The caller enqueues the BullMQ job with the returned row's id.
async function createModuleBuildRequest({
  deviceId, username, buildinfoUploadId, kernelRelease, isa, endianness,
  deviceVermagic, configArtifactPath,
}) {
  const { ModuleBuildRequest } = getModels();
  const userId = await resolveUserId(username);
  return ModuleBuildRequest.create({
    deviceId,
    userId,
    buildinfoUploadId,
    status: 'queued',
    kernelRelease,
    isa,
    endianness,
    deviceVermagic: deviceVermagic || null,
    configArtifactPath: configArtifactPath || null,
  });
}

// Find an already-succeeded build for this device whose compiled .ko can be
// reused for an identical target, newest first. The build is a pure function of
// (kernelRelease, isa, endianness, vermagic), and vermagic is precisely the
// kernel-module compatibility contract, so a matching artifact is load-
// equivalent to a fresh compile. Only rows that still carry an artifactPath are
// returned; the caller must confirm the file is present on disk before reusing
// it (the volume may have been wiped).
async function findReusableModuleBuild(deviceId, {
  kernelRelease, isa, endianness, deviceVermagic,
}) {
  const { ModuleBuildRequest } = getModels();
  return ModuleBuildRequest.findOne({
    where: {
      deviceId,
      status: 'succeeded',
      artifactPath: { [Op.ne]: null },
      kernelRelease,
      isa: isa ?? null,
      endianness: endianness ?? null,
      deviceVermagic: deviceVermagic ?? null,
    },
    order: [['id', 'DESC']],
  });
}

// Builder-worker transitions. Each is a single targeted update by primary key.
async function markBuildStarted(requestId) {
  const { ModuleBuildRequest } = getModels();
  await ModuleBuildRequest.update(
    { status: 'building' },
    { where: { id: requestId } },
  );
}

async function markBuildSucceeded(requestId, { builtVermagic, vermagicResult, source, artifactPath }) {
  const { ModuleBuildRequest } = getModels();
  await ModuleBuildRequest.update({
    status: 'succeeded',
    builtVermagic: builtVermagic || null,
    vermagicResult: vermagicResult || null,
    source: source || null,
    artifactPath: artifactPath || null,
    errorMessage: null,
  }, { where: { id: requestId } });
}

async function markBuildFailed(requestId, errorMessage) {
  const { ModuleBuildRequest } = getModels();
  await ModuleBuildRequest.update({
    status: 'failed',
    errorMessage: String(errorMessage || 'unknown error').slice(0, 4000),
  }, { where: { id: requestId } });
}

// Device ids associated with `username`, optionally narrowed to one MAC.
// Same non-enumerating semantics as clientUploads.resolveUserDeviceIds.
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

// List build requests visible to `username` (their associated devices only),
// newest first. Optional mac narrows to one device.
async function listModuleBuildRequests(username, { mac = null, limit = 100 } = {}) {
  const deviceIds = await resolveUserDeviceIds(username, { mac });
  if (!deviceIds.length) {
    return [];
  }
  const { ModuleBuildRequest } = getModels();
  return ModuleBuildRequest.findAll({
    where: { deviceId: deviceIds },
    order: [['id', 'DESC']],
    limit,
  });
}

// Mint a one-time download token for a succeeded build. The raw token is
// returned to the caller (to embed in the download-file command) and only its
// sha256 lands in the DB. Re-issuing replaces any previous token.
async function issueDownloadToken(requestId, { ttlMs = DEFAULT_TOKEN_TTL_MS } = {}) {
  const { ModuleBuildRequest } = getModels();
  const token = crypto.randomBytes(32).toString('hex');
  // null ttl => non-expiring token (invalidated only by single use).
  const expiresAt = ttlMs == null ? null : new Date(Date.now() + ttlMs);
  const [updated] = await ModuleBuildRequest.update({
    downloadTokenHash: hashToken(token),
    downloadTokenExpiresAt: expiresAt,
  }, {
    where: { id: requestId, status: 'succeeded' },
  });
  if (!updated) {
    return null;
  }
  return { token, expiresAt };
}

// Resolve a presented download token to its build request: hash must match,
// not expired, artifact present. A null downloadTokenExpiresAt means the token
// has no time-based expiry (see DEFAULT_TOKEN_TTL_MS) and is valid until used;
// single use is guaranteed by clearing the hash, not by the expiry. On success
// the hash is cleared atomically (single-use); a second request with the same
// token 404s. Returns the row or null — the caller cannot distinguish
// unknown/expired/used, by design.
async function consumeDownloadToken(token) {
  const { ModuleBuildRequest } = getModels();
  const row = await ModuleBuildRequest.findOne({
    where: { downloadTokenHash: hashToken(String(token || '')) },
  });
  if (!row || !row.artifactPath) {
    return null;
  }
  if (row.downloadTokenExpiresAt && row.downloadTokenExpiresAt.getTime() < Date.now()) {
    return null;
  }
  // Single-use: only the request that clears the hash serves the file, so
  // two concurrent fetches of one token cannot both succeed.
  const [cleared] = await ModuleBuildRequest.update({
    downloadTokenHash: null,
    downloadTokenExpiresAt: null,
  }, {
    where: { id: row.id, downloadTokenHash: row.downloadTokenHash },
  });
  return cleared ? row : null;
}

// One build request by id, only when it belongs to a device associated with
// `username`. Returns null (indistinguishable from not-found) otherwise.
async function getModuleBuildRequest(username, id) {
  const deviceIds = await resolveUserDeviceIds(username);
  if (!deviceIds.length) {
    return null;
  }
  const { ModuleBuildRequest } = getModels();
  return ModuleBuildRequest.findOne({
    where: { id, deviceId: deviceIds },
  });
}

module.exports = {
  latestBuildInfoForDevice,
  latestKernelConfigPath,
  findReusableModuleBuild,
  createModuleBuildRequest,
  markBuildStarted,
  markBuildSucceeded,
  markBuildFailed,
  listModuleBuildRequests,
  getModuleBuildRequest,
  issueDownloadToken,
  consumeDownloadToken,
};
