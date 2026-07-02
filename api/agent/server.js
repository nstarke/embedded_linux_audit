#!/usr/bin/env node

'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const http = require('http');
const https = require('https');
const path = require('path');
const { execFileSync } = require('child_process');
const auth = require('../auth');
const { getAgentServiceConfig } = require('../lib/config');
const { initializeDatabase, runMigrations, closeDatabase } = require('../lib/db');
const { persistUpload } = require('../lib/db/persistUpload');
const { loadApiKeyHashes } = require('../lib/db/deviceRegistry');
const { VALID_UPLOAD_TYPES } = require('../lib/uploadTypes');
const { createApp } = require('./app');
const { createPcapWebSocketServer } = require('./pcapWebSocket');
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
const VALID_CONTENT_TYPES = {
  'text/plain': 'text_plain',
  'text/csv': 'text_csv',
  'application/json': 'application_json',
  'application/x-ndjson': 'application_x_ndjson',
  'application/octet-stream': 'application_octet_stream'
};

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
  const serviceDefaults = getAgentServiceConfig();
  const defaults = {
    host: serviceDefaults.host,
    port: serviceDefaults.port,
    logPrefix: serviceDefaults.logPrefix,
    dataDir: serviceDefaults.dataDir,
    assetsDir: serviceDefaults.assetsDir,
    testsDir: serviceDefaults.testsDir,
    clean: defaultClean,
    https: false,
    verbose: defaultVerbose,
    cert: 'tools/certs/localhost.crt',
    key: 'tools/certs/localhost.key',
  };

  const args = { ...defaults };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--host': args.host = argv[++i]; break;
      case '--port': args.port = Number(argv[++i]); break;
      case '--log-prefix': args.logPrefix = argv[++i]; break;
      case '--data-dir': args.dataDir = argv[++i]; break;
      case '--assets-dir': args.assetsDir = argv[++i]; break;
      case '--tests-dir': args.testsDir = argv[++i]; break;
      case '--clean': args.clean = true; break;
      case '--https': args.https = true; break;
      case '--verbose': args.verbose = true; break;
      case '--cert': args.cert = argv[++i]; break;
      case '--key': args.key = argv[++i]; break;
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
  console.log(`Usage: node server.js [options]\n\nOptions:\n  --host HOST\n  --port PORT\n  --log-prefix PREFIX\n  --data-dir DIR\n  --assets-dir DIR\n  --tests-dir DIR\n  --clean\n  --https\n  --verbose\n  --cert PATH\n  --key PATH\n  --reuse-last-data-dir  Reuse the latest timestamped data directory instead of creating a new one\n  --help`);
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

  if (!await auth.init(false, () => loadApiKeyHashes('agent'))) {
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
  const usersAssetsDir = path.join(assetsDir, 'users');

  if (args.clean) {
    await removeDirectoryContents(dataRootDir, new Set(['release_binaries']));
  }

  await Promise.all([
    fsp.mkdir(dataRootDir, { recursive: true }),
    fsp.mkdir(dataDir, { recursive: true }),
    fsp.mkdir(defaultAssetsDir, { recursive: true }),
    fsp.mkdir(usersAssetsDir, { recursive: true })
  ]);

  if (args.reuseLastDataDir) {
    const action = startupDataDir.reusedExisting ? 'Reusing' : 'Created';
    console.log(`${action} startup data directory ${dataDir}`);
  }

  console.log(`Serving per-user agent binaries from ${usersAssetsDir}/<keyHash>; shared fallback ${assetsDir}`);
  console.log('Build per-user binaries with: node tools/add-user-key.js --username <name>');

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

  createPcapWebSocketServer({
    server,
    dataDir,
    persistUpload,
    verbose: args.verbose,
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(args.port, args.host, resolve);
  });

  console.log(`Listening on ${scheme}://${args.host}:${args.port}/`);
  console.log(`PCAP WebSocket listening on ${scheme === 'https' ? 'wss' : 'ws'}://${args.host}:${args.port}/pcap/<mac>`);
  console.log(`Logging POST requests with prefix: ${logPrefix}`);
  console.log('Per-type logs: <prefix>.text_plain.log, <prefix>.text_csv.log, <prefix>.application_octet_stream.log');
  console.log('GET / shows index of per-user release binaries, test shell scripts, and command scripts');

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
  createPcapWebSocketServer,
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
