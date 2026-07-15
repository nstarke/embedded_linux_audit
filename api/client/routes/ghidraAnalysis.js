// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const path = require('path');
const fsp = require('fs/promises');
const { spawn } = require('child_process');

// Walk the decompiler output root and return every "binary" directory — a
// program subdirectory Haruspex populated with at least one .c file — as a
// path relative to the output root (the value the download route's ?binary=
// takes), with its .c file count. Symlinks are not followed.
async function listOutputBinaries(outputRoot, fs = fsp) {
  const out = [];
  async function walk(dir) {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const cFiles = entries.filter((e) => e.isFile() && e.name.endsWith('.c'));
    if (cFiles.length) {
      out.push({ binary: path.relative(outputRoot, dir), files: cFiles.length });
    }
    for (const entry of entries) {
      if (entry.isDirectory() && !entry.isSymbolicLink()) {
        await walk(path.join(dir, entry.name));
      }
    }
  }
  await walk(outputRoot);
  out.sort((a, b) => a.binary.localeCompare(b.binary));
  return out;
}

// Same separator-insensitive MAC handling as the terminal / module-build routes.
const MAC_ADDRESS_RE = /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/;

// Lazily resolve DB/queue helpers so importing this module in tests does not
// pull in sequelize (mirrors routes/moduleBuilds.js).
function ghidraJobs() {
  return require('../../lib/db/ghidraJobs');
}
function deviceRegistry() {
  return require('../../lib/db/deviceRegistry');
}
function defaultGetQueue() {
  return require('../../lib/queue').getGhidraAnalysisQueue();
}

function serializeJob(row) {
  return {
    id: row.id,
    status: row.status,
    filesFound: row.filesFound,
    filesAnalyzed: row.filesAnalyzed,
    outputRoot: row.outputRoot,
    errorMessage: row.errorMessage,
    createdAt: row.created_at || row.createdAt,
    updatedAt: row.updated_at || row.updatedAt,
  };
}

function macKey(mac) {
  return String(mac || '').toLowerCase().replace(/[^0-9a-f]/g, '');
}

/**
 * Operator routes for Ghidra decompilation jobs:
 *
 *   POST /devices/:mac/ghidra-analysis  — pull the device rootfs via
 *       `linux remote-copy --recursive /` and decompile every ELF with Ghidra.
 *       Returns 202 with the created job; the ghidra-analysis worker runs it.
 *   GET  /ghidra-analysis               — list the caller's jobs (?mac= filter).
 *   GET  /ghidra-analysis/:id           — one job's status/progress.
 *
 * ACL matches the rest of the client API: everything is scoped to devices
 * associated with the authenticated user; a device the caller is not
 * associated with is indistinguishable from an unknown one (404).
 *
 * @param {object} app
 * @param {object} deps  Test injection: db, getQueue, listUserDeviceMacs, findDeviceByMac.
 */
module.exports = function registerGhidraAnalysisRoutes(app, deps = {}) {
  const db = {
    createGhidraJob: (...args) => ghidraJobs().createGhidraJob(...args),
    listGhidraJobs: (...args) => ghidraJobs().listGhidraJobs(...args),
    getGhidraJob: (...args) => ghidraJobs().getGhidraJob(...args),
    ...deps.db,
  };
  const getQueue = deps.getQueue || defaultGetQueue;
  // How the zip download is produced. Default streams `zip -r - .` from the
  // job's output directory; injectable for tests.
  const spawnZip = deps.spawnZip
    || ((cwd, args) => spawn('zip', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] }));
  const statDir = deps.statDir
    || (async (p) => {
      try {
        return (await fsp.stat(p)).isDirectory();
      } catch {
        return false;
      }
    });
  const walkOutputs = deps.walkOutputs || listOutputBinaries;
  const listUserDeviceMacs = deps.listUserDeviceMacs
    || ((username) => deviceRegistry().listUserDeviceMacs(username));
  const findDeviceByMac = deps.findDeviceByMac
    || (async (mac) => {
      const { Device } = require('../../lib/db/index').getModels();
      const { normalizeMac } = deviceRegistry();
      return Device.findOne({ where: { macAddress: normalizeMac(mac) } });
    });

  /*
   * Create a ghidra-analysis job for a device and enqueue it. The heavy work
   * (remote-copy of the rootfs + recursive analyzeHeadless decompile) runs in
   * the ghidra-analysis worker, so this returns 202 immediately and the caller
   * polls GET /ghidra-analysis/:id.
   */
  app.post('/devices/:mac/ghidra-analysis', async (req, res) => {
    const mac = String(req.params.mac || '');
    if (!MAC_ADDRESS_RE.test(mac)) {
      res.status(400).json({ error: 'invalid mac address' });
      return;
    }

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

    const job = await db.createGhidraJob({ deviceId: device.id, username: req.authUser });

    // The worker reaches the live agent session (to trigger remote-copy) via
    // the terminal command queue itself, so the payload only needs the job
    // identity and the device MAC.
    await getQueue().add('ghidra-analysis', {
      jobId: job.id,
      deviceId: device.id,
      mac: storedMac,
    }, {
      attempts: 1,
      removeOnComplete: true,
      removeOnFail: true,
    });

    res.status(202).json({ ghidraAnalysis: serializeJob(job) });
  });

  app.get('/ghidra-analysis', async (req, res) => {
    const mac = req.query.mac === undefined ? null : String(req.query.mac);
    if (mac !== null && macKey(mac).length !== 12) {
      res.status(400).json({ error: 'invalid mac address' });
      return;
    }
    const rows = await db.listGhidraJobs(req.authUser, { mac });
    res.json({ ghidraAnalyses: rows.map(serializeJob) });
  });

  app.get('/ghidra-analysis/:id', async (req, res) => {
    const id = String(req.params.id || '');
    if (!/^[0-9]+$/.test(id)) {
      res.status(400).json({ error: 'invalid id' });
      return;
    }
    const row = await db.getGhidraJob(req.authUser, Number.parseInt(id, 10));
    if (!row) {
      res.status(404).json({ error: 'ghidra analysis not found' });
      return;
    }
    res.json({ ghidraAnalysis: serializeJob(row) });
  });

  /*
   * List the decompiler outputs available for a job: one entry per binary
   * (a program subdirectory with .c files), with the relative path the download
   * route's ?binary= accepts and its .c file count. Lets a client discover what
   * is downloadable without guessing binary paths.
   */
  app.get('/ghidra-analysis/:id/outputs', async (req, res) => {
    const id = String(req.params.id || '');
    if (!/^[0-9]+$/.test(id)) {
      res.status(400).json({ error: 'invalid id' });
      return;
    }
    const row = await db.getGhidraJob(req.authUser, Number.parseInt(id, 10));
    if (!row) {
      res.status(404).json({ error: 'ghidra analysis not found' });
      return;
    }
    if (row.status !== 'succeeded' || !row.outputRoot) {
      res.status(409).json({ error: `ghidra analysis output is not available (status: ${row.status})` });
      return;
    }
    const binaries = await walkOutputs(path.resolve(row.outputRoot));
    res.json({ outputs: binaries });
  });

  /*
   * Stream a zip of the Haruspex decompiler output for a job. By default the
   * archive holds every binary's `<programName>/<func@addr>.c` tree; pass
   * ?binary=<relative-dir> to scope it to one binary's subdirectory (as
   * reported in the fs hierarchy, e.g. `usr/bin/busybox`). The output lives on
   * the shared /data volume mounted read-only into the client API.
   */
  app.get('/ghidra-analysis/:id/output.zip', async (req, res) => {
    const id = String(req.params.id || '');
    if (!/^[0-9]+$/.test(id)) {
      res.status(400).json({ error: 'invalid id' });
      return;
    }
    const row = await db.getGhidraJob(req.authUser, Number.parseInt(id, 10));
    if (!row) {
      res.status(404).json({ error: 'ghidra analysis not found' });
      return;
    }
    if (row.status !== 'succeeded' || !row.outputRoot) {
      res.status(409).json({ error: `ghidra analysis output is not available (status: ${row.status})` });
      return;
    }

    // Optionally scope to one binary's subdirectory. Resolve and confirm it
    // stays within outputRoot so a crafted ?binary= cannot escape the tree.
    const outputRoot = path.resolve(row.outputRoot);
    let target = outputRoot;
    let zipArg = '.';
    const binary = req.query.binary;
    if (binary !== undefined) {
      if (typeof binary !== 'string' || !binary.length) {
        res.status(400).json({ error: 'invalid binary' });
        return;
      }
      const resolved = path.resolve(outputRoot, binary);
      const rel = path.relative(outputRoot, resolved);
      if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
        res.status(400).json({ error: 'invalid binary' });
        return;
      }
      // zip runs with cwd=outputRoot and archives the relative subpath, so the
      // entries keep their hierarchy inside the archive.
      zipArg = rel;
      target = resolved;
    }

    if (!await statDir(target)) {
      res.status(404).json({ error: 'no output for this binary' });
      return;
    }

    const filename = `ghidra-analysis-${row.id}${binary ? `-${path.basename(zipArg)}` : ''}.zip`;
    res.status(200);
    res.type('application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // `zip -r - <path>` writes the archive to stdout; stream it straight to the
    // client. Recurse, and store (not compress) nothing special — .c text zips
    // well with the default deflate.
    const child = spawnZip(outputRoot, ['-r', '-q', '-', zipArg]);
    let failed = false;
    child.on('error', () => {
      failed = true;
      if (!res.headersSent) {
        res.status(500).json({ error: 'failed to create archive' });
      } else {
        res.destroy();
      }
    });
    child.stdout.pipe(res);
    child.on('close', (code) => {
      if (!failed && code !== 0 && !res.writableEnded) {
        // Non-zero after headers are already flushed: just end the (partial)
        // stream; the truncated zip will fail to open, signalling the error.
        res.end();
      }
    });
    // If the client disconnects mid-stream, stop zipping.
    res.on('close', () => {
      if (!child.killed) {
        try { child.kill('SIGKILL'); } catch { /* already gone */ }
      }
    });
  });
};
