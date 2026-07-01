#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

/**
 * Force a rebuild of the one-time GENERIC (unembedded) agent binaries.
 *
 * The builder worker only auto-compiles the generic binaries when the generic
 * dir is empty (see api/builder/worker.js bootstrapGenericBuild). After changing
 * the agent sources, use this to recompile them on demand: it enqueues a
 * `generic` build job onto the same queue the builder worker consumes, so the
 * cross-compile runs inside the builder container (with its toolchain) and
 * overwrites <assetsDir>/generic/ela-<isa>.
 *
 * This does NOT re-wrap per-user launchers — run tools/rebuild-launchers.js
 * afterwards to fold the fresh generic binaries into each user's launcher.
 *
 * Usage (run inside the stack so it can reach Redis + the assets volume):
 *   docker compose exec builder node /app/tools/rebuild-generic.js [--assets-dir <dir>]
 *
 * The job is consumed by the builder container regardless of which service you
 * run this from; any service sharing the Redis connection works.
 */

const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const { resolveAssetsDir, genericDir } = require(path.join(repoRoot, 'api/lib/agentAssets'));
const { getBuildQueue, closeBuildQueue, QUEUE_NAME } = require(path.join(repoRoot, 'api/lib/queue'));

function getArg(flag) {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 ? process.argv[idx + 1] : null;
}

const assetsDirArg = getArg('--assets-dir');

async function main() {
  const assetsDir = resolveAssetsDir({ assetsDirArg, repoRoot });
  const outDir = genericDir(assetsDir);
  const queue = getBuildQueue();

  // Fixed jobId so repeated invocations coalesce into a single pending rebuild
  // rather than stacking up. removeOnComplete/Fail clears the record afterward
  // so the next rebuild is never blocked by a lingering job of the same id.
  const job = await queue.add('generic', { outDir }, {
    jobId: 'generic-rebuild',
    attempts: 1,
    removeOnComplete: true,
    removeOnFail: true,
  });

  process.stdout.write(`enqueued generic rebuild on "${QUEUE_NAME}" (job ${job.id}) -> ${outDir}\n`);
  process.stdout.write('The builder worker compiles every ISA; watch it with:\n');
  process.stdout.write('  docker compose logs -f builder\n');
  process.stdout.write('  node tools/build-status.js\n');
  process.stdout.write('When it finishes, run tools/rebuild-launchers.js to update user launchers.\n');

  await closeBuildQueue();
}

main().catch((err) => {
  process.stderr.write(`error: ${err.message}\n`);
  closeBuildQueue().catch(() => {}).finally(() => process.exit(1));
});
