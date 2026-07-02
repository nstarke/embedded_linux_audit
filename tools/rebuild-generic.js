#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

/**
 * Force a rebuild of the one-time GENERIC (unembedded) agent binaries.
 *
 * The builder worker only auto-compiles them when the generic dir is empty (see
 * api/builder/worker.js bootstrapGenericBuild), so after changing the agent
 * sources there is otherwise no way to recompile without wiping that dir. This
 * runs the SAME compile the worker runs (api/builder/runBuild -> the release
 * build script), synchronously, overwriting <assetsDir>/generic/ela-<isa>.
 *
 * It deliberately does NOT touch the build queue, so it depends only on Node
 * builtins (no bullmq / node_modules) and runs straight from the /src bind-mount
 * inside the builder container — the one place with the cross-compile toolchain:
 *
 *   docker compose exec builder node /src/tools/rebuild-generic.js
 *
 * This does NOT re-wrap per-user launchers — run tools/rebuild-launchers.js
 * afterwards to fold the fresh generic binaries into each user's launcher.
 *
 * Usage:
 *   node tools/rebuild-generic.js [--assets-dir <dir>]
 */

const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const { resolveAssetsDir, genericDir } = require(path.join(repoRoot, 'api/lib/agentAssets'));
const { runBuild } = require(path.join(repoRoot, 'api/builder/runBuild'));

function getArg(flag) {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 ? process.argv[idx + 1] : null;
}

const assetsDirArg = getArg('--assets-dir');

async function main() {
  const assetsDir = resolveAssetsDir({ assetsDirArg, repoRoot });
  const outDir = genericDir(assetsDir);

  process.stdout.write(`recompiling generic agent binaries -> ${outDir}\n`);
  process.stdout.write('(cross-compiling every ISA; this takes several minutes)\n\n');

  // Same code path as the builder worker: spawns the release build script with
  // RELEASE_BINARIES_DIR=outDir and flat output, streaming its logs here. A
  // generic build bakes in no token/URL (no embeddedKey/serverUrl passed).
  await runBuild({ outDir });

  process.stdout.write(`\ndone: generic binaries written to ${outDir}\n`);
  process.stdout.write('Next: node tools/rebuild-launchers.js --server-url <wss://host> to update user launchers.\n');
}

main().catch((err) => {
  process.stderr.write(`error: ${err.message}\n`);
  process.exit(1);
});
