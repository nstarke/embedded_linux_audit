// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const path = require('path');
const fsp = require('fs/promises');
const { spawn } = require('child_process');
const { resolveTarget, parseKernelRelease, compareVermagic } = require('./kernelTarget');

// Where the repo (kmod/ sources + build script) is mounted in the builder
// container. Same mount as the binary builds.
const DEFAULT_REPO_ROOT = process.env.ELA_BUILD_REPO_ROOT || '/src';

/**
 * Run one kernel-module build job: compile kmod/ against the upstream kernel
 * matching the device's kernel release, then compare the built vermagic
 * against the device's.
 *
 * The job payload carries the device's module-buildinfo facts (as persisted
 * by the module-buildinfo upload) plus where to write the artifact:
 *   {
 *     outDir:         string   — artifact directory (required)
 *     kernelRelease:  string   — e.g. "3.12.19-rt30" (required)
 *     isa:            string   — e.g. "arm32" (required)
 *     endianness:     string   — e.g. "little" (required)
 *     vermagic:       string?  — device vermagic to compare against
 *     configPath:     string?  — stored kernel-config artifact (.gz or plain)
 *   }
 *
 * Resolves with:
 *   {
 *     outDir, koPath, builtVermagic,
 *     vermagicResult: 'match'|'release-match'|'mismatch'|'unverified',
 *     source: 'upstream-exact'|'upstream-nearest',
 *   }
 * 'upstream-nearest' means the device release had a local suffix (vendor
 * kernel); we built the nearest upstream base with LOCALVERSION re-applied.
 *
 * Like runBuild: asynchronous spawn so the BullMQ lock keeps renewing during
 * the (potentially long) modules_prepare step.
 *
 * @param {object} payload
 * @param {{spawn?:Function, repoRoot?:string, fsp?:object}} [opts]  Test injection.
 */
function runModuleBuild(payload, opts = {}) {
  const spawnImpl = opts.spawn || spawn;
  const fspImpl = opts.fsp || fsp;
  const repoRoot = opts.repoRoot || DEFAULT_REPO_ROOT;
  const {
    outDir, kernelRelease, isa, endianness, vermagic, configPath,
  } = payload || {};

  if (!outDir) {
    return Promise.reject(new Error('module build job missing outDir'));
  }

  const parsed = parseKernelRelease(kernelRelease);
  if (!parsed) {
    return Promise.reject(new Error(`unparseable kernel release: ${kernelRelease}`));
  }

  const target = resolveTarget({ isa, endianness });
  if (!target) {
    return Promise.reject(new Error(`unsupported build target: isa=${isa} endianness=${endianness}`));
  }

  const script = path.join(repoRoot, 'api/builder/build-kernel-module.sh');
  const buildEnv = {
    ...process.env,
    ELA_KMOD_KERNEL_VERSION: parsed.version,
    ELA_KMOD_LOCALVERSION: parsed.localVersion,
    ELA_KMOD_ARCH: target.arch,
    ELA_KMOD_CROSS_COMPILE: target.crossCompile,
    ELA_KMOD_OUT_DIR: outDir,
  };
  if (configPath) {
    buildEnv.ELA_KMOD_CONFIG_PATH = configPath;
  }

  return new Promise((resolve, reject) => {
    const child = spawnImpl('sh', [script], {
      cwd: repoRoot,
      stdio: 'inherit',
      env: buildEnv,
    });

    child.on('error', (err) => {
      reject(new Error(`failed to launch module build script: ${err.message}`));
    });
    child.on('close', async (code) => {
      if (code !== 0) {
        reject(new Error(`module build script exited with status ${code}`));
        return;
      }
      try {
        const koPath = path.join(outDir, 'ela_kmod.ko');
        const builtVermagic = (await fspImpl.readFile(path.join(outDir, 'vermagic.txt'), 'utf8')).trim();
        resolve({
          outDir,
          koPath,
          builtVermagic,
          vermagicResult: vermagic ? compareVermagic(builtVermagic, vermagic) : 'unverified',
          source: parsed.localVersion ? 'upstream-nearest' : 'upstream-exact',
        });
      } catch (err) {
        reject(new Error(`module build produced no readable artifacts: ${err.message}`));
      }
    });
  });
}

module.exports = { runModuleBuild, DEFAULT_REPO_ROOT };
