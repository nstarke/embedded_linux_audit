// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');

// Same separator-insensitive MAC handling as the terminal routes.
const MAC_ADDRESS_RE = /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/;

// Lazily resolve DB helpers so importing this module in tests does not pull in
// sequelize (mirrors routes/terminal.js).
function moduleBuilds() {
  return require('../../lib/db/moduleBuilds');
}
function deviceRegistry() {
  return require('../../lib/db/deviceRegistry');
}
function kernelTarget() {
  return require('../../builder/kernelTarget');
}
function defaultGetQueue() {
  return require('../../lib/queue').getModuleBuildQueue();
}
function defaultSendCommand(payload, opts) {
  return require('../../lib/queue').sendTerminalCommand(payload, opts);
}

function serializeRequest(row) {
  return {
    id: row.id,
    status: row.status,
    kernelRelease: row.kernelRelease,
    isa: row.isa,
    endianness: row.endianness,
    deviceVermagic: row.deviceVermagic,
    builtVermagic: row.builtVermagic,
    vermagicResult: row.vermagicResult,
    source: row.source,
    errorMessage: row.errorMessage,
    createdAt: row.created_at || row.createdAt,
    updatedAt: row.updated_at || row.updatedAt,
  };
}

// A kernel that refuses the module for a vermagic/format reason surfaces
// ENOEXEC, which the agent reports as "Exec format error", "Invalid module
// format", or a "version magic '...' should be '...'" line. Scan the whole
// agent result for any of these so we can react by re-delivering a
// vermagic-patched copy.
function looksLikeVermagicReject(result) {
  if (!result) {
    return false;
  }
  const hay = JSON.stringify(result).toLowerCase();
  return hay.includes('exec format error')
    || hay.includes('invalid module format')
    || hay.includes('version magic');
}

/**
 * Operator routes for kernel-module builds:
 *
 *   POST /devices/:mac/module-builds  — create a build request from the
 *       device's latest module-buildinfo upload and enqueue it.
 *   GET  /module-builds               — list the caller's requests (?mac= filter).
 *   GET  /module-builds/:id           — one request's status/result.
 *
 * ACL matches the rest of the client API: everything is scoped to devices
 * associated with the authenticated user; a device the caller is not
 * associated with is indistinguishable from an unknown one (404).
 *
 * @param {object} app
 * @param {object} deps  Test injection: db, resolveDevice, getQueue, dataDir.
 */
module.exports = function registerModuleBuildRoutes(app, deps = {}) {
  const db = {
    latestBuildInfoForDevice: (...args) => moduleBuilds().latestBuildInfoForDevice(...args),
    latestKernelConfigPath: (...args) => moduleBuilds().latestKernelConfigPath(...args),
    findReusableModuleBuild: (...args) => moduleBuilds().findReusableModuleBuild(...args),
    createModuleBuildRequest: (...args) => moduleBuilds().createModuleBuildRequest(...args),
    listModuleBuildRequests: (...args) => moduleBuilds().listModuleBuildRequests(...args),
    getModuleBuildRequest: (...args) => moduleBuilds().getModuleBuildRequest(...args),
    issueDownloadToken: (...args) => moduleBuilds().issueDownloadToken(...args),
    ...deps.db,
  };
  const sendCommand = deps.sendCommand || defaultSendCommand;
  const recordCommandLog = deps.recordCommandLog
    || ((row) => deviceRegistry().recordCommandLog(row));
  // Where the agent reaches the agent-api from ITS network vantage point
  // (the docker-internal name the client API uses would not resolve on the
  // device). Deployments set this to the public agent-api origin.
  const moduleBaseUrl = deps.moduleBaseUrl || process.env.ELA_MODULE_DOWNLOAD_BASE_URL || null;
  const parseBody = deps.parseBody || express.json({ limit: 64 * 1024, type: () => true });
  const sleep = deps.sleep || ((ms) => new Promise((resolve) => { setTimeout(resolve, ms); }));
  // How long to wait for the buildinfo upload to land after pushing the
  // command: the agent runs it in a second or two, but the upload arrives on
  // a separate HTTP path after the exec returns.
  const autobuildWaitMs = deps.autobuildWaitMs ?? 20000;
  const autobuildPollMs = deps.autobuildPollMs ?? 1000;

  /*
   * Push `linux modules buildinfo` to the live agent session and wait for the
   * resulting module-buildinfo upload to supersede `previousUploadId`.
   * Returns the fresh {upload, buildInfo} or null (agent offline, command
   * failed, or the upload never arrived in time).
   */
  async function refreshBuildInfo(username, mac, deviceId, previousUploadId) {
    let result;
    try {
      result = await sendCommand(
        { type: 'exec', mode: 'ela', mac, command: 'linux modules buildinfo' },
        { waitMs: 30000 },
      );
    } catch {
      result = { status: 504 };
    }
    await recordCommandLog({
      username,
      macAddress: mac,
      commandType: 'module-autobuild',
      command: 'linux modules buildinfo',
      status: result && result.status,
    }).catch(() => {});
    if (!result || result.status !== 200) {
      return null;
    }

    const deadline = Date.now() + autobuildWaitMs;
    for (;;) {
      const latest = await db.latestBuildInfoForDevice(deviceId);
      if (latest && latest.upload.id !== previousUploadId) {
        return latest;
      }
      if (Date.now() >= deadline) {
        return null;
      }
      await sleep(autobuildPollMs);
    }
  }
  const listUserDeviceMacs = deps.listUserDeviceMacs
    || ((username) => deviceRegistry().listUserDeviceMacs(username));
  const findDeviceByMac = deps.findDeviceByMac
    || (async (mac) => {
      const { Device } = require('../../lib/db/index').getModels();
      const { normalizeMac } = deviceRegistry();
      return Device.findOne({ where: { macAddress: normalizeMac(mac) } });
    });
  const findDeviceById = deps.findDeviceById
    || (async (id) => {
      const { Device } = require('../../lib/db/index').getModels();
      return Device.findByPk(id);
    });
  const getQueue = deps.getQueue || defaultGetQueue;
  const dataDir = deps.dataDir || process.env.ELA_AGENT_DATA_DIR || 'api/agent/data';
  // Confirm a reuse candidate's compiled .ko is still on the shared volume
  // before handing it back instead of rebuilding.
  const artifactExists = deps.artifactExists
    || (async (p) => {
      try {
        return (await fs.promises.stat(p)).isFile();
      } catch {
        return false;
      }
    });

  function macKey(mac) {
    return String(mac || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  }

  /*
   * Create a build request from the device's latest module-buildinfo upload.
   *
   * Body (optional): { autobuild: true } — first push `linux modules
   * buildinfo` to the live agent session and wait for the fresh upload, so
   * the build uses current kernel facts (and works on devices that have
   * never uploaded buildinfo). Without autobuild, a device with no buildinfo
   * upload is a 409.
   */
  app.post('/devices/:mac/module-builds', parseBody, async (req, res) => {
    const mac = String(req.params.mac || '');
    if (!MAC_ADDRESS_RE.test(mac)) {
      res.status(400).json({ error: 'invalid mac address' });
      return;
    }
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const autobuild = body.autobuild === true;

    // ACL: resolve the requested MAC within the caller's associated devices.
    let macs;
    try {
      macs = await listUserDeviceMacs(req.authUser);
    } catch {
      res.status(503).json({ error: 'device registry unavailable' });
      return;
    }
    const storedMac = macs.find((m) => macKey(m) === macKey(mac));
    if (!storedMac) {
      res.status(404).json({ error: 'device not found' });
      return;
    }

    const device = await findDeviceByMac(storedMac);
    if (!device) {
      res.status(404).json({ error: 'device not found' });
      return;
    }

    let latest = await db.latestBuildInfoForDevice(device.id);
    if (autobuild) {
      // Always refresh: stale facts after a kernel update would build the
      // wrong module. The previous upload id tells the poll what "fresh" is.
      const refreshed = await refreshBuildInfo(
        req.authUser, storedMac, device.id, latest ? latest.upload.id : null,
      );
      if (!refreshed) {
        res.status(504).json({
          error: 'autobuild failed: agent did not produce a module-buildinfo upload (device offline?)',
        });
        return;
      }
      latest = refreshed;
    }
    if (!latest) {
      res.status(409).json({
        error: 'no module-buildinfo upload for this device; run `linux modules buildinfo` on the agent first or pass autobuild:true',
      });
      return;
    }
    const { upload, buildInfo } = latest;

    if (!buildInfo.kernelRelease || !kernelTarget().parseKernelRelease(buildInfo.kernelRelease)) {
      res.status(422).json({ error: `device kernel release is unusable for builds: ${buildInfo.kernelRelease}` });
      return;
    }
    if (!kernelTarget().resolveTarget(buildInfo)) {
      res.status(422).json({
        error: `no cross toolchain for isa=${buildInfo.isa} endianness=${buildInfo.endianness}`,
      });
      return;
    }

    // If this exact target was already compiled for the device and the .ko is
    // still on disk, reuse it instead of queueing a duplicate build — the
    // artifact would be byte-for-byte identical. Returns 200 (not 202) so the
    // caller can tell an immediate hit from a freshly queued build.
    const reusable = await db.findReusableModuleBuild(device.id, {
      kernelRelease: buildInfo.kernelRelease,
      isa: buildInfo.isa,
      endianness: buildInfo.endianness,
      deviceVermagic: buildInfo.vermagic,
    });
    if (reusable && await artifactExists(reusable.artifactPath)) {
      res.status(200).json({ moduleBuild: serializeRequest(reusable), reused: true });
      return;
    }

    const configPath = buildInfo.configAvailable
      ? await db.latestKernelConfigPath(device.id)
      : null;

    const request = await db.createModuleBuildRequest({
      deviceId: device.id,
      username: req.authUser,
      buildinfoUploadId: upload.id,
      kernelRelease: buildInfo.kernelRelease,
      isa: buildInfo.isa,
      endianness: buildInfo.endianness,
      deviceVermagic: buildInfo.vermagic,
      configArtifactPath: configPath,
    });

    // Artifacts land under the device's data dir on the shared volume, where
    // the agent-api can later serve them (Phase 5 download route).
    const outDir = path.join(dataDir, storedMac, 'modules', String(request.id));
    await getQueue().add('module-build', {
      requestId: request.id,
      outDir,
      kernelRelease: buildInfo.kernelRelease,
      isa: buildInfo.isa,
      endianness: buildInfo.endianness,
      vermagic: buildInfo.vermagic,
      configPath,
    }, {
      attempts: 1,
      removeOnComplete: true,
      removeOnFail: true,
    });

    res.status(202).json({ moduleBuild: serializeRequest(request) });
  });

  app.get('/module-builds', async (req, res) => {
    const mac = req.query.mac === undefined ? null : String(req.query.mac);
    if (mac !== null && macKey(mac).length !== 12) {
      res.status(400).json({ error: 'invalid mac address' });
      return;
    }
    const rows = await db.listModuleBuildRequests(req.authUser, { mac });
    res.json({ moduleBuilds: rows.map(serializeRequest) });
  });

  /*
   * Deliver a succeeded build to its device: mint a one-time download token,
   * then push `linux download-file` + `linux modules load` to the live agent
   * session over the terminal command queue.
   *
   * Body (all optional):
   *   baseUrl   agent-api origin as reachable FROM THE DEVICE; falls back to
   *             ELA_MODULE_DOWNLOAD_BASE_URL. Required one way or the other.
   *   load      false to only download (default true: download then load)
   *   force     true to load with --force (vermagic mismatch override);
   *             defaults to true when the build's vermagicResult was not an
   *             exact 'match', since a plain load would be refused anyway.
   *   destPath  where the .ko lands on the device (default /tmp/ela_kmod.ko)
   */
  app.post('/module-builds/:id/deliver', parseBody, async (req, res) => {
    const id = String(req.params.id || '');
    if (!/^[0-9]+$/.test(id)) {
      res.status(400).json({ error: 'invalid id' });
      return;
    }

    // getModuleBuildRequest is user-scoped, so this doubles as the ACL.
    const row = await db.getModuleBuildRequest(req.authUser, Number.parseInt(id, 10));
    if (!row) {
      res.status(404).json({ error: 'module build not found' });
      return;
    }
    if (row.status !== 'succeeded' || !row.artifactPath) {
      res.status(409).json({ error: `module build is not deliverable (status: ${row.status})` });
      return;
    }

    const body = req.body && typeof req.body === 'object' ? req.body : {};
    // Strip trailing slashes with a plain loop rather than a `/\/+$/` regex:
    // the regex backtracks polynomially on inputs with many '/' characters
    // (CodeQL js/polynomial-redos), and this input is user-supplied.
    let baseUrl = String(body.baseUrl || moduleBaseUrl || '').trim();
    let baseEnd = baseUrl.length;
    while (baseEnd > 0 && baseUrl.charCodeAt(baseEnd - 1) === 47 /* '/' */) {
      baseEnd -= 1;
    }
    baseUrl = baseUrl.slice(0, baseEnd);
    if (!/^https?:\/\//i.test(baseUrl)) {
      res.status(400).json({
        error: 'baseUrl (agent-reachable agent-api origin) is required; set it in the body or ELA_MODULE_DOWNLOAD_BASE_URL',
      });
      return;
    }
    const destPath = typeof body.destPath === 'string' && body.destPath.startsWith('/')
      ? body.destPath
      : '/tmp/ela_kmod.ko';
    if (/[\s"'`;|&]/.test(destPath)) {
      res.status(400).json({ error: 'invalid destPath' });
      return;
    }
    const load = body.load !== false;
    const force = typeof body.force === 'boolean'
      ? body.force
      : row.vermagicResult !== 'match';

    const device = await findDeviceById(row.deviceId);
    if (!device) {
      res.status(404).json({ error: 'module build not found' });
      return;
    }

    const issued = await db.issueDownloadToken(row.id);
    if (!issued) {
      res.status(409).json({ error: 'could not issue download token' });
      return;
    }

    // Run one raw ELA command over the live terminal session, audit-log it with
    // the token redacted (the log must not become a second copy of the
    // credential), record the result, and return it.
    const results = [];
    const runDeliverStep = async (command, token, commandType) => {
      let result;
      try {
        result = await sendCommand(
          { type: 'exec', mode: 'ela', mac: device.macAddress, command },
          { waitMs: 60000 },
        );
      } catch {
        result = { status: 504, body: { error: 'terminal command timed out or terminal API unavailable' } };
      }
      const redacted = command.split(token).join('<token>');
      await recordCommandLog({
        username: req.authUser,
        macAddress: device.macAddress,
        commandType,
        command: redacted,
        status: result && result.status,
      }).catch(() => {});
      results.push({ command: redacted, ...result });
      return result;
    };

    // Same download+run shape the self-update flow uses.
    const dl = await runDeliverStep(
      `linux download-file ${baseUrl}/module/${issued.token} ${destPath}`,
      issued.token, 'module-deliver',
    );
    let lastLoad = null;
    if (load && dl && dl.status === 200) {
      lastLoad = await runDeliverStep(
        `linux modules load${force ? ' --force' : ''} ${destPath}`,
        issued.token, 'module-deliver',
      );
    }

    // Reactive vermagic patch: a kernel built without CONFIG_MODULE_FORCE_LOAD
    // ignores --force, so a vermagic mismatch still fails the load with ENOEXEC
    // ("Exec format error"). When we know the device's vermagic, mint a fresh
    // token and re-deliver the SAME module with its .modinfo vermagic rewritten
    // to match — the agent-api patches it at serve time when the download URL
    // carries ?vermagic=device — then load without --force since it now matches.
    let vermagicPatched = false;
    if (load && row.deviceVermagic && looksLikeVermagicReject(lastLoad)) {
      const patchTok = await db.issueDownloadToken(row.id);
      if (patchTok) {
        vermagicPatched = true;
        const pdl = await runDeliverStep(
          `linux download-file ${baseUrl}/module/${patchTok.token}?vermagic=device ${destPath}`,
          patchTok.token, 'module-deliver-patched',
        );
        if (pdl && pdl.status === 200) {
          lastLoad = await runDeliverStep(
            `linux modules load ${destPath}`, patchTok.token, 'module-deliver-patched',
          );
        }
      }
    }

    const delivered = load
      ? Boolean(lastLoad && lastLoad.status === 200 && !looksLikeVermagicReject(lastLoad))
      : Boolean(dl && dl.status === 200);
    res.status(delivered ? 200 : 502).json({
      delivered,
      force,
      vermagicPatched,
      destPath,
      tokenExpiresAt: issued.expiresAt,
      results,
    });
  });

  app.get('/module-builds/:id', async (req, res) => {
    const id = String(req.params.id || '');
    if (!/^[0-9]+$/.test(id)) {
      res.status(400).json({ error: 'invalid id' });
      return;
    }
    const row = await db.getModuleBuildRequest(req.authUser, Number.parseInt(id, 10));
    if (!row) {
      res.status(404).json({ error: 'module build not found' });
      return;
    }
    res.json({ moduleBuild: serializeRequest(row) });
  });
};
