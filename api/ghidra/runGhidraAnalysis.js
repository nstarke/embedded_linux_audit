// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const path = require('path');
const fsp = require('fs/promises');
const os = require('os');
const { findElfFiles } = require('./findElfFiles');
const { runAnalyzeHeadless } = require('./analyzeHeadless');

const DEFAULT_DATA_DIR = process.env.ELA_AGENT_DATA_DIR || '/data/agent';

// The whole-rootfs remote-copy runs entirely on the agent between the exec
// request and the returning prompt, so it can take many minutes. Give it a
// generous (env-overridable) exec + client wait. These stay well under the
// worker's 6h BullMQ lock.
const DEFAULT_COPY_TIMEOUT_MS = Number.parseInt(process.env.ELA_GHIDRA_COPY_TIMEOUT_MS || String(60 * 60 * 1000), 10);

// Given a `file` upload's stored artifact path (…/<data>/<macDir>/fs/<abs>),
// recover the <data>/<macDir>/fs root. The macDir is the first path segment
// under dataDir; deriving it from a real artifact avoids reconstructing the
// agent's egress-NIC MAC formatting.
function fsRootFromArtifactPath(dataDir, artifactPath) {
  const rel = path.relative(dataDir, artifactPath);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    return null;
  }
  const macDir = rel.split(path.sep)[0];
  if (!macDir) {
    return null;
  }
  return path.join(dataDir, macDir, 'fs');
}

// Count the program subdirectories Haruspex created under the output root as a
// proxy for "binaries actually decompiled". Each loaded program gets its own
// `<programName>/` directory; we count those that contain at least one .c file.
async function countAnalyzed(outputRoot, fs = fsp) {
  let entries;
  try {
    entries = await fs.readdir(outputRoot, { withFileTypes: true });
  } catch {
    return 0;
  }
  let analyzed = 0;
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const sub = path.join(outputRoot, entry.name);
    const inner = await fs.readdir(sub).catch(() => []);
    if (inner.some((n) => n.endsWith('.c'))) {
      analyzed += 1;
    }
  }
  return analyzed;
}

/**
 * Run one full ghidra-analysis job:
 *   1. copying   — push `linux remote-copy --recursive /` to the live agent
 *      session and wait for it to finish uploading the rootfs (minus the
 *      /dev, /proc, /sys mounts remote-copy refuses without --allow-* flags).
 *   2. analyzing — hand the uploaded fs root to a single recursive
 *      analyzeHeadless run; Ghidra discovers every loadable binary and the
 *      Haruspex post-script writes decompiled C into a parallel `ghidra/` tree.
 *
 * Status transitions and progress counters are written through `db` so
 * operators can poll GET /ghidra-analysis/:id while the job runs. DB writes are
 * best-effort (a status-write failure must not abort the analysis).
 *
 * @param {object} payload  { jobId, deviceId, mac }
 * @param {object} deps
 *   db            ghidra-jobs DB helpers (markCopying/markAnalyzing/…, latestFilesystemUploadPath)
 *   sendCommand   (payload, opts) => terminal-command promise (remote-copy trigger)
 *   analyze       runAnalyzeHeadless override (tests)
 *   scan          findElfFiles override (tests)
 *   dataDir, fsp, log
 * @returns {Promise<{fsRoot, outputRoot, filesFound, filesAnalyzed}>}
 */
async function runGhidraAnalysis(payload, deps = {}) {
  const { jobId, deviceId, mac } = payload || {};
  const db = deps.db || require('../lib/db/ghidraJobs');
  const sendCommand = deps.sendCommand
    || ((cmd, opts) => require('../lib/queue').sendTerminalCommand(cmd, opts));
  const analyze = deps.analyze || runAnalyzeHeadless;
  const scan = deps.scan || findElfFiles;
  const dataDir = deps.dataDir || DEFAULT_DATA_DIR;
  const fs = deps.fsp || fsp;
  const log = deps.log || (() => {});
  const copyTimeoutMs = deps.copyTimeoutMs ?? DEFAULT_COPY_TIMEOUT_MS;

  if (!jobId || !deviceId || !mac) {
    throw new Error('ghidra-analysis job missing jobId, deviceId or mac');
  }

  // 1. Pull the device filesystem over the live agent session.
  await db.markCopying(jobId).catch((e) => log(`markCopying failed: ${e && e.message}`));
  log(`[ghidra] job=${jobId} mac=${mac}: requesting remote-copy --recursive /`);
  try {
    await sendCommand(
      {
        type: 'exec',
        mode: 'ela',
        mac,
        command: 'linux remote-copy --recursive /',
        timeoutMs: copyTimeoutMs,
      },
      { waitMs: copyTimeoutMs + 30000 },
    );
  } catch (err) {
    // The copy result is confirmed by the landed uploads below, not by the exec
    // response — a slow copy can outrun the exec wait yet still upload files.
    log(`[ghidra] job=${jobId}: remote-copy exec did not return cleanly (${err && err.message}); checking for uploads`);
  }

  // 2. Resolve where the upload actually landed on the shared volume.
  const artifactPath = await db.latestFilesystemUploadPath(deviceId);
  if (!artifactPath) {
    throw new Error('no filesystem uploads landed for this device (remote-copy produced nothing; device offline?)');
  }
  const fsRoot = fsRootFromArtifactPath(dataDir, artifactPath);
  if (!fsRoot) {
    throw new Error(`could not resolve fs root from artifact path: ${artifactPath}`);
  }
  const outputRoot = path.join(path.dirname(fsRoot), 'ghidra');
  await fs.mkdir(outputRoot, { recursive: true });

  // Count the ELFs Ghidra will encounter (reporting only — discovery itself is
  // Ghidra's recursive import below).
  const { files, skippedLarge } = await scan(fsRoot);
  log(`[ghidra] job=${jobId}: fsRoot=${fsRoot} elfCount=${files.length} skippedLarge=${skippedLarge}`);

  await db.markAnalyzing(jobId, { fsRoot, outputRoot, filesFound: files.length })
    .catch((e) => log(`markAnalyzing failed: ${e && e.message}`));

  // 3. One recursive analyzeHeadless pass over the whole uploaded tree.
  const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ela-ghidra-'));
  try {
    const result = await analyze({
      importTarget: fsRoot,
      recursive: true,
      outputBase: outputRoot,
      projectDir,
      projectName: `ela-ghidra-job-${jobId}`,
      log,
    });
    log(`[ghidra] job=${jobId}: analyzeHeadless exit=${result.code} timedOut=${result.timedOut}`);
    if (result.timedOut) {
      throw new Error('analyzeHeadless exceeded its invocation timeout');
    }
    if (result.code !== 0) {
      throw new Error(`analyzeHeadless exited ${result.code}`);
    }
  } finally {
    await fs.rm(projectDir, { recursive: true, force: true }).catch(() => {});
  }

  const filesAnalyzed = await countAnalyzed(outputRoot, fs);
  await db.markSucceeded(jobId, { filesFound: files.length, filesAnalyzed, outputRoot })
    .catch((e) => log(`markSucceeded failed: ${e && e.message}`));

  return { fsRoot, outputRoot, filesFound: files.length, filesAnalyzed };
}

module.exports = {
  runGhidraAnalysis,
  fsRootFromArtifactPath,
  countAnalyzed,
};
