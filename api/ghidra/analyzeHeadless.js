// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

// Where Ghidra is installed in the ghidra-worker image (api/ghidra/Dockerfile
// unpacks the release here and exposes support/analyzeHeadless).
const DEFAULT_GHIDRA_HOME = process.env.GHIDRA_HOME || '/opt/ghidra';
// The decompiler post-script lives next to this file and is copied into the
// image; -scriptPath points Ghidra at its directory.
const DEFAULT_SCRIPT_DIR = __dirname;
const POST_SCRIPT = 'HaruspexHeadless.java';

function analyzeHeadlessBin(ghidraHome) {
  return path.join(ghidraHome, 'support', 'analyzeHeadless');
}

/**
 * Run one `analyzeHeadless` invocation over an import target and run the
 * Haruspex decompiler post-script against every program it loads.
 *
 * With `recursive: true` and `importTarget` set to the uploaded filesystem
 * root, Ghidra itself walks the tree and imports every file it recognizes as a
 * loadable binary (ELF executables, shared objects and kernel modules),
 * skipping everything it cannot load — so binary discovery is Ghidra's job, not
 * ours.
 *
 * `outputBase` and `importTarget` are passed as the post-script's args, so
 * Haruspex writes to `<outputBase>/<path-within-fs>/<func@addr>.c` — mirroring
 * each binary's location in the imported filesystem tree, kept out of the `fs/`
 * tree that holds the uploaded binaries themselves.
 *
 * @param {object} opts
 * @param {string}   opts.importTarget   Absolute path to import (the fs root).
 * @param {boolean}  [opts.recursive]    Recurse into subdirectories (default true).
 * @param {string}   opts.outputBase     Dir Haruspex writes program subdirs into.
 * @param {string}   opts.projectDir     Ghidra project location (temp; deleted after).
 * @param {string}   opts.projectName    Ghidra project name.
 * @param {string}   [opts.ghidraHome]
 * @param {string}   [opts.scriptDir]
 * @param {number}   [opts.analysisTimeoutSec]  Per-file auto-analysis cap.
 * @param {number}   [opts.overallTimeoutMs]    Hard kill for the whole invocation.
 * @param {Function} [opts.spawn]         Injected child_process.spawn (tests).
 * @param {Function} [opts.log]
 * @returns {Promise<{code:number, timedOut:boolean, argv:string[]}>}
 */
function runAnalyzeHeadless(opts = {}) {
  const {
    importTarget,
    recursive = true,
    outputBase,
    projectDir,
    projectName,
    ghidraHome = DEFAULT_GHIDRA_HOME,
    scriptDir = DEFAULT_SCRIPT_DIR,
    analysisTimeoutSec = Number.parseInt(process.env.ELA_GHIDRA_ANALYSIS_TIMEOUT_SEC || '600', 10),
    overallTimeoutMs = Number.parseInt(process.env.ELA_GHIDRA_INVOCATION_TIMEOUT_MS || String(6 * 60 * 60 * 1000), 10),
    spawn: spawnImpl = spawn,
    log = () => {},
  } = opts;

  if (!importTarget || !outputBase || !projectDir || !projectName) {
    return Promise.reject(new Error('runAnalyzeHeadless: importTarget, outputBase, projectDir and projectName are required'));
  }

  const argv = [
    projectDir,
    projectName,
    '-import', importTarget,
  ];
  if (recursive) {
    argv.push('-recursive');
  }
  argv.push(
    '-scriptPath', scriptDir,
    // Haruspex args: <outputBase> <importRoot>. The import root lets it place
    // each binary's output at its path within the fs tree, not a flat basename.
    '-postScript', POST_SCRIPT, outputBase, importTarget,
    '-analysisTimeoutPerFile', String(analysisTimeoutSec),
    // Fresh throwaway project; -deleteProject reclaims it when the run ends.
    '-deleteProject',
  );

  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnImpl(analyzeHeadlessBin(ghidraHome), argv, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, TMPDIR: process.env.TMPDIR || os.tmpdir() },
      });
    } catch (err) {
      reject(err);
      return;
    }

    let timedOut = false;
    const timer = overallTimeoutMs > 0 ? setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
    }, overallTimeoutMs) : null;

    if (child.stdout) {
      child.stdout.on('data', (d) => log(String(d)));
    }
    if (child.stderr) {
      child.stderr.on('data', (d) => log(String(d)));
    }

    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      resolve({ code: code == null ? -1 : code, timedOut, argv });
    });
  });
}

module.exports = {
  runAnalyzeHeadless,
  analyzeHeadlessBin,
  DEFAULT_GHIDRA_HOME,
  POST_SCRIPT,
};
