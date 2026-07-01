// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const path = require('path');
const { getAgentServiceConfig } = require('./config');

// Shared agent-binary directory layout, used by the agent helper server, the
// builder worker, and the provisioning tools so they all agree on paths:
//   <assetsDir>/generic/ela-<isa>        one-time generic (unembedded) binaries
//   <assetsDir>/users/<keyHash>/ela-<isa> per-user self-extracting launchers
const GENERIC_SUBDIR = 'generic';
const USERS_SUBDIR = 'users';

// Repo root relative to this file (api/lib/agentAssets.js -> repo root).
const REPO_ROOT = path.resolve(__dirname, '..', '..');

/**
 * Resolve the assets directory the agent helper server serves from, matching
 * the tools and server: an explicit --assets-dir wins, then
 * ELA_AGENT_ASSETS_DIR, then <dataDir>/release_binaries. Relative paths are
 * resolved against the repo root.
 */
function resolveAssetsDir({ assetsDirArg = null, repoRoot = REPO_ROOT } = {}) {
  if (assetsDirArg) {
    return path.isAbsolute(assetsDirArg) ? assetsDirArg : path.resolve(repoRoot, assetsDirArg);
  }
  const svc = getAgentServiceConfig();
  if (svc.assetsDir) {
    return path.isAbsolute(svc.assetsDir) ? svc.assetsDir : path.resolve(repoRoot, svc.assetsDir);
  }
  const dataRoot = path.isAbsolute(svc.dataDir) ? svc.dataDir : path.resolve(repoRoot, svc.dataDir);
  return path.join(dataRoot, 'release_binaries');
}

function genericDir(assetsDir) {
  return path.join(assetsDir, GENERIC_SUBDIR);
}

function userDir(assetsDir, keyHash) {
  return path.join(assetsDir, USERS_SUBDIR, keyHash);
}

module.exports = {
  GENERIC_SUBDIR,
  USERS_SUBDIR,
  resolveAssetsDir,
  genericDir,
  userDir,
};
