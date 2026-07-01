'use strict';

const path = require('path');
const { spawn } = require('child_process');

// Where the repo (sources to compile) is mounted in the builder container.
const DEFAULT_REPO_ROOT = process.env.ELA_BUILD_REPO_ROOT || '/src';

/**
 * Run a binary build for one queue job.
 *
 * The default (and only) job in the new model is a GENERIC build: no token or
 * URL is baked in — those are injected at runtime by the per-user self-extracting
 * launcher (see api/agent/selfExtract.js). If `embeddedKey` is present the legacy
 * embed path still works (token compiled in), for back-compat.
 *
 * Asynchronous on purpose: the compile takes many minutes, so it must not block
 * the worker's event loop (BullMQ needs to keep renewing the job lock). The
 * child is spawned and we resolve/reject on its exit.
 *
 * @param {{outDir:string, embeddedKey?:string, serverUrl?:string, username?:string, keyHash?:string}} payload
 * @param {{spawn?:Function, repoRoot?:string}} [opts]  Injection point for tests.
 * @returns {Promise<{outDir:string}>}
 */
function runBuild(payload, opts = {}) {
  const spawnImpl = opts.spawn || spawn;
  const repoRoot = opts.repoRoot || DEFAULT_REPO_ROOT;
  const { embeddedKey, outDir, serverUrl } = payload || {};

  if (!outDir) {
    return Promise.reject(new Error('build job missing outDir'));
  }

  const script = path.join(repoRoot, 'tests/compile_release_binaries_locally.sh');
  const buildEnv = {
    ...process.env,
    // The compile script derives its output dir from RELEASE_BINARIES_DIR
    // (DEST_RELEASE_DIR is set for readability but the script reassigns it).
    RELEASE_BINARIES_DIR: outDir,
    DEST_RELEASE_DIR: outDir,
    ELA_RELEASE_FLAT_OUTPUT: '1',
  };
  // Legacy embed path: bake the token / URL in only when provided. Generic
  // builds omit both.
  if (embeddedKey) {
    buildEnv.ELA_EMBEDDED_API_KEY = embeddedKey;
  }
  if (serverUrl) {
    buildEnv.ELA_EMBEDDED_SERVER_URL = serverUrl;
  }

  return new Promise((resolve, reject) => {
    // Invoked via `sh` so the script's file mode does not matter. The build
    // writes intermediate artifacts under repoRoot and the final flat binaries
    // into DEST_RELEASE_DIR (the per-user dir on the shared data volume).
    const child = spawnImpl('sh', [script], {
      cwd: repoRoot,
      stdio: 'inherit',
      env: buildEnv,
    });

    child.on('error', (err) => {
      reject(new Error(`failed to launch build script: ${err.message}`));
    });
    child.on('close', (code) => {
      if (code === 0) {
        resolve({ outDir });
      } else {
        reject(new Error(`build script exited with status ${code}`));
      }
    });
  });
}

module.exports = { runBuild, DEFAULT_REPO_ROOT };
