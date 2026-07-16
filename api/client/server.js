#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const http = require('http');
const auth = require('../auth');
const { getClientServiceConfig } = require('../lib/config');
const { initializeDatabase, runMigrations, closeDatabase } = require('../lib/db');
const { loadApiKeyHashes } = require('../lib/db/deviceRegistry');
const { closeCommandQueue } = require('../lib/queue');
const { closeSnapshotClient } = require('../lib/sessionSnapshot');
const { createApp } = require('./app');

async function main() {
  try {
    await initializeDatabase();
    await runMigrations();
  } catch (err) {
    console.error(`Failed to initialize database: ${err.message}`);
    return 1;
  }

  // Client keys are read from the database per request; enforcement is dynamic
  // (any client key existing -> a valid client token is required). The app also
  // requires a resolved user on every route, so with no client keys configured
  // every request is rejected for lack of a user.
  await auth.init(false, () => loadApiKeyHashes('client'));

  const { host, port } = getClientServiceConfig();
  const app = createApp();
  const server = http.createServer(app);

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });

  console.log(`ELA client API listening on http://${host}:${port}/`);
  console.log('Routes: GET /uploads[...]; GET /terminal/sessions; POST /terminal/sessions/:mac; POST /terminal/:mac/{linux,ela}/{exec,spawn}; GET|DELETE /terminal/:mac/spawn[/:pid]');

  process.on('SIGINT', () => {
    server.close(async () => {
      await closeCommandQueue().catch(() => {});
      await closeSnapshotClient().catch(() => {});
      await closeDatabase().catch(() => {});
      process.exit(0);
    });
  });

  return 0;
}

module.exports = { main };

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
