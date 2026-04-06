#!/usr/bin/env node

'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const http = require('http');
const https = require('https');
const path = require('path');
const crypto = require('crypto');
const mime = require('mime-types');
const { execFileSync } = require('child_process');
const auth = require('../auth');
const { getAgentServiceConfig } = require('../lib/config');
const { initializeDatabase, runMigrations, closeDatabase } = require('../lib/db');
const { persistUpload } = require('../lib/db/persistUpload');
const { loadApiKeyHashes } = require('../lib/db/deviceRegistry');
const { createApp } = require('./app');
const {
  findProjectRoot,
  isValidMacAddress,
  normalizeContentType,
  logPathForContentType,
  augmentJsonPayload,
  resolveProjectPath,
  selectStartupDataDir,
  isWithinRoot,
  getClientIp,
  sanitizeUploadPath,
  writeUploadFile,
} = require('./serverUtils');

const RELEASE_STATE_FILE = '.release_state.json';

const PROJECT_ROOT = findProjectRoot(__dirname);
const WEB_ROOT = __dirname;
const VALID_UPLOAD_TYPES = new Set(['arch', 'cmd', 'dmesg', 'efi-vars', 'file', 'file-list', 'grep', 'log', 'logs', 'orom', 'symlink-list', 'tpm2-createprimary', 'tpm2-getcap', 'tpm2-nvreadpublic', 'tpm2-pcrread', 'uboot-image', 'uboot-environment']);
const VALID_CONTENT_TYPES = {
  'text/plain': 'text_plain',
  'text/csv': 'text_csv',
  'application/json': 'application_json',
  'application/x-ndjson': 'application_x_ndjson',
  'application/octet-stream': 'application_octet_stream'
};

function githubJsonGet(url, token) {
  return new Promise((resolve, reject) => {
    const headers = {
      'User-Agent': 'embedded_linux_audit-web_server_helper',
      'Accept': 'application/vnd.github+json'
    };
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    https.get(url, { headers }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        if (res.statusCode && res.statusCode >= 400) {
          const error = new Error(`HTTP ${res.statusCode}`);
          error.statusCode = res.statusCode;
          return reject(error);
        }
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(err);
        }
      });
    }).on('error', reject);
  });
}

function requestUrl(url, headers) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const req = client.get(url, { headers }, (res) => {
      resolve(res);
    });
    req.on('error', reject);
  });
}

async function downloadFile(url, destPath, token, redirectCount = 0) {
  if (redirectCount > 5) {
    throw new Error('Too many redirects');
  }

  return new Promise((resolve, reject) => {
    const headers = {
      'User-Agent': 'embedded_linux_audit-web_server_helper'
    };
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    const file = fs.createWriteStream(destPath);
    const client = url.startsWith('https:') ? https : http;
    client.get(url, { headers }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const redirectUrl = new URL(res.headers.location, url).toString();
        res.resume();
        file.close(async () => {
          fs.rm(destPath, { force: true }, async () => {
            try {
              await downloadFile(redirectUrl, destPath, token, redirectCount + 1);
              resolve();
            } catch (err) {
              reject(err);
            }
          });
        });
        return;
      }

      if (res.statusCode && res.statusCode >= 400) {
        res.resume();
        file.close(() => fs.rm(destPath, { force: true }, () => {}));
        return reject(new Error(`HTTP ${res.statusCode}`));
      }

      res.pipe(file);
      file.on('finish', () => file.close(resolve));
    }).on('error', (err) => {
      file.close(() => fs.rm(destPath, { force: true }, () => {}));
      reject(err);
    });
  });
}

async function getLatestRelease(repo, token) {
  return githubJsonGet(`https://api.github.com/repos/${repo}/releases/latest`, token);
}

function releaseIdentity(release) {
  if (release.tag_name) {
    return String(release.tag_name);
  }
  if (release.id !== undefined && release.id !== null) {
    return String(release.id);
  }
  return '';
}

async function loadCachedReleaseIdentity(outDir) {
  const statePath = path.join(outDir, RELEASE_STATE_FILE);
  try {
    const state = JSON.parse(await fsp.readFile(statePath, 'utf8'));
    return typeof state.release === 'string' && state.release ? state.release : null;
  } catch {
    return null;
  }
}

async function saveCachedReleaseIdentity(outDir, release) {
  const statePath = path.join(outDir, RELEASE_STATE_FILE);
  const state = {
    release,
    updated_at: new Date().toISOString()
  };
  await fsp.mkdir(outDir, { recursive: true });
  await fsp.writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`, 'utf8');
}

async function clearDownloadedAssets(outDir) {
  try {
    const entries = await fsp.readdir(outDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === RELEASE_STATE_FILE) {
        continue;
      }
      if (entry.isFile() || entry.isSymbolicLink()) {
        await fsp.unlink(path.join(outDir, entry.name));
      }
    }
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw err;
    }
  }
}

async function removeDirectoryContents(dirPath, preservedNames = new Set()) {
  try {
    const entries = await fsp.readdir(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      if (preservedNames.has(entry.name)) {
        continue;
      }
      const fullPath = path.join(dirPath, entry.name);
      await fsp.rm(fullPath, { recursive: true, force: true });
    }
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw err;
    }
  }
}

async function downloadReleaseAssets(release, outDir, token, forceDownload) {
  await fsp.mkdir(outDir, { recursive: true });
  const assets = Array.isArray(release.assets) ? release.assets : [];
  const downloaded = [];
  const skippedExisting = [];

  for (const asset of assets) {
    const name = asset.name;
    const downloadUrl = asset.browser_download_url;
    if (!name || !downloadUrl) {
      continue;
    }

    const dest = path.join(outDir, name);
    if (!forceDownload) {
      try {
        await fsp.access(dest, fs.constants.F_OK);
        skippedExisting.push(dest);
        continue;
      } catch {
        // continue to download
      }
    }

    await downloadFile(downloadUrl, dest, token);
    downloaded.push(dest);
  }

  return { downloaded, skippedExisting };
}

function ensureSelfSignedCert(certPath, keyPath) {
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return;
  }

  const openssl = 'openssl';
  fs.mkdirSync(path.dirname(certPath), { recursive: true });
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  execFileSync(openssl, [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-sha256',
    '-days',
    '3650',
    '-nodes',
    '-subj',
    '/CN=localhost',
    '-addext',
    'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-keyout',
    keyPath,
    '-out',
    certPath
  ], { stdio: 'ignore' });
}

function parseArgs(argv) {
  const npmBoolean = (name) => String(process.env[name] || '').toLowerCase() === 'true';
  const npmLogLevel = String(process.env.npm_config_loglevel || '').toLowerCase();
  const defaultVerbose = ['verbose', 'silly'].includes(npmLogLevel);
  const defaultClean = npmBoolean('npm_config_clean');
  const defaultForceDownload = npmBoolean('npm_config_force_download');
  const serviceDefaults = getAgentServiceConfig();
  const defaults = {
    host: serviceDefaults.host,
    port: serviceDefaults.port,
    logPrefix: serviceDefaults.logPrefix,
    dataDir: serviceDefaults.dataDir,
    repo: serviceDefaults.repo,
    assetsDir: serviceDefaults.assetsDir,
    testsDir: serviceDefaults.testsDir,
    githubToken: process.env.GITHUB_TOKEN || '',
    forceDownload: defaultForceDownload,
    clean: defaultClean,
    https: false,
    verbose: defaultVerbose,
    cert: 'tools/certs/localhost.crt',
    key: 'tools/certs/localhost.key',
    skipAssetSync: String(process.env.ELA_AGENT_SKIP_ASSET_SYNC || '').toLowerCase() === 'true',
  };

  const args = { ...defaults };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--host': args.host = argv[++i]; break;
      case '--port': args.port = Number(argv[++i]); break;
      case '--log-prefix': args.logPrefix = argv[++i]; break;
      case '--data-dir': args.dataDir = argv[++i]; break;
      case '--repo': args.repo = argv[++i]; break;
      case '--assets-dir': args.assetsDir = argv[++i]; break;
      case '--tests-dir': args.testsDir = argv[++i]; break;
      case '--github-token': args.githubToken = argv[++i]; break;
      case '--force-download': args.forceDownload = true; break;
      case '--clean': args.clean = true; break;
      case '--https': args.https = true; break;
      case '--verbose': args.verbose = true; break;
      case '--cert': args.cert = argv[++i]; break;
      case '--key': args.key = argv[++i]; break;
      case '--skip-asset-sync': args.skipAssetSync = true; break;
      case '--reuse-last-data-dir': args.reuseLastDataDir = true; break;
      case '--help':
        printHelp();
        process.exit(0);
        break;
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!Number.isInteger(args.port) || args.port < 1 || args.port > 65535) {
    throw new Error(`Invalid --port value: ${args.port}`);
  }

  return args;
}

function printHelp() {
  console.log(`Usage: node server.js [options]\n\nOptions:\n  --host HOST\n  --port PORT\n  --log-prefix PREFIX\n  --data-dir DIR\n  --repo OWNER/NAME\n  --assets-dir DIR\n  --tests-dir DIR\n  --github-token TOKEN\n  --force-download\n  --clean\n  --https\n  --verbose\n  --cert PATH\n  --key PATH\n  --skip-asset-sync  Skip GitHub release asset refresh during startup\n  --reuse-last-data-dir  Reuse the latest timestamped data directory instead of creating a new one\n  --help`);
}
  
async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(err.message);
    printHelp();
    return 1;
  }

  try {
    await initializeDatabase();
    await runMigrations();
  } catch (err) {
    console.error(`Failed to initialize database: ${err.message}`);
    return 1;
  }

  if (!await auth.init(true, loadApiKeyHashes)) {
    console.error('error: no API keys are configured in the database');
    return 1;
  }

  const logPrefix = resolveProjectPath(PROJECT_ROOT, args.logPrefix);
  const dataRootDir = resolveProjectPath(PROJECT_ROOT, args.dataDir);
  const startupDataDir = await selectStartupDataDir(dataRootDir, {
    reuseLastTimestampDir: Boolean(args.reuseLastDataDir),
  });
  const dataDir = startupDataDir.dataDir;
  const defaultAssetsDir = path.join(dataRootDir, 'release_binaries');
  const assetsDir = args.assetsDir
    ? (path.isAbsolute(args.assetsDir)
      ? args.assetsDir
      : path.resolve(dataDir, args.assetsDir))
    : defaultAssetsDir;
  const testsDir = resolveProjectPath(PROJECT_ROOT, args.testsDir);
  const token = args.githubToken || null;

  if (args.clean) {
    await removeDirectoryContents(dataRootDir, new Set(['release_binaries']));
  }

  await Promise.all([
    fsp.mkdir(dataRootDir, { recursive: true }),
    fsp.mkdir(dataDir, { recursive: true }),
    fsp.mkdir(defaultAssetsDir, { recursive: true })
  ]);

  if (args.reuseLastDataDir) {
    const action = startupDataDir.reusedExisting ? 'Reusing' : 'Created';
    console.log(`${action} startup data directory ${dataDir}`);
  }

  if (args.skipAssetSync) {
    console.log(`Skipping release asset sync; serving assets from ${assetsDir}`);
  } else {
    try {
      const latestRelease = await getLatestRelease(args.repo, token);
      const latestReleaseId = releaseIdentity(latestRelease);
      const cachedReleaseId = await loadCachedReleaseIdentity(assetsDir);
      const isNewRelease = Boolean(latestReleaseId) && latestReleaseId !== cachedReleaseId;

      let result;
      if (args.forceDownload) {
        console.log('Force download enabled; refreshing release binaries');
        await clearDownloadedAssets(assetsDir);
        result = await downloadReleaseAssets(latestRelease, assetsDir, token, true);
        if (latestReleaseId) {
          await saveCachedReleaseIdentity(assetsDir, latestReleaseId);
        }
      } else if (isNewRelease) {
        console.log(`New release detected (${cachedReleaseId || '<none>'} -> ${latestReleaseId}); refreshing binaries`);
        await clearDownloadedAssets(assetsDir);
        result = await downloadReleaseAssets(latestRelease, assetsDir, token, true);
        await saveCachedReleaseIdentity(assetsDir, latestReleaseId);
      } else {
        console.log('No new release detected; keeping existing binaries');
        result = await downloadReleaseAssets(latestRelease, assetsDir, token, false);
        if (latestReleaseId && cachedReleaseId !== latestReleaseId) {
          await saveCachedReleaseIdentity(assetsDir, latestReleaseId);
        }
      }

      console.log(`Downloaded ${result.downloaded.length} release asset(s) from ${args.repo} into ${assetsDir}`);
      if (result.skippedExisting.length) {
        console.log(`Skipped ${result.skippedExisting.length} existing release asset(s) in ${assetsDir} (use --force-download to replace them)`);
      }
    } catch (err) {
      console.error(`Failed to fetch/download release assets from ${args.repo}: ${err.message}`);
      return 1;
    }
  }

  const app = createApp({
    logPrefix,
    assetsDir,
    dataDir,
    testsDir,
    verbose: args.verbose,
    releaseStateFile: RELEASE_STATE_FILE,
    validUploadTypes: VALID_UPLOAD_TYPES,
    validContentTypes: VALID_CONTENT_TYPES,
    persistUpload,
  });
  let server;
  let scheme = 'http';

  if (args.https) {
    const certPath = resolveProjectPath(PROJECT_ROOT, args.cert);
    const keyPath = resolveProjectPath(PROJECT_ROOT, args.key);
    ensureSelfSignedCert(certPath, keyPath);
    server = https.createServer({
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath)
    }, app);
    scheme = 'https';
  } else {
    server = http.createServer(app);
  }

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(args.port, args.host, resolve);
  });

  console.log(`Listening on ${scheme}://${args.host}:${args.port}/`);
  console.log(`Logging POST requests with prefix: ${logPrefix}`);
  console.log('Per-type logs: <prefix>.text_plain.log, <prefix>.text_csv.log, <prefix>.application_octet_stream.log');
  console.log('GET / shows index of downloaded release binaries, test shell scripts, and command scripts');

  process.on('SIGINT', () => {
    server.close(async () => {
      await closeDatabase().catch(() => {});
      process.exit(0);
    });
  });

  return 0;
}

module.exports = {
  RELEASE_STATE_FILE,
  PROJECT_ROOT,
  WEB_ROOT,
  VALID_UPLOAD_TYPES,
  VALID_CONTENT_TYPES,
  githubJsonGet,
  requestUrl,
  downloadFile,
  getLatestRelease,
  releaseIdentity,
  loadCachedReleaseIdentity,
  saveCachedReleaseIdentity,
  clearDownloadedAssets,
  downloadReleaseAssets,
  ensureSelfSignedCert,
  isValidMacAddress,
  normalizeContentType,
  logPathForContentType,
  augmentJsonPayload,
  resolveProjectPath,
  isWithinRoot,
  getClientIp,
  sanitizeUploadPath,
  writeUploadFile,
  removeDirectoryContents,
  createApp,
  parseArgs,
  printHelp,
  main
};

if (require.main === module) {
  main().then((code) => {
    if (code !== 0) {
      process.exit(code);
    }
  }).catch((err) => {
    console.error(err.stack || err.message);
    process.exit(1);
  });
}
