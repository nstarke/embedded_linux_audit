#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const http = require('http');
const auth = require('../auth');
const { getClientServiceConfig } = require('../lib/config');
const { initializeDatabase, runMigrations, closeDatabase } = require('../lib/db');
const { loadApiKeyHashes } = require('../lib/db/deviceRegistry');
const { createApp } = require('./app');

async function main() {
  try {
    await initializeDatabase();
    await runMigrations();
  } catch (err) {
    console.error(`Failed to initialize database: ${err.message}`);
    return 1;
  }

  // Load client-scoped keys once at startup.  Enforce auth only when at least
  // one client key exists so the service still starts on a fresh stack; the
  // app additionally requires a resolved user on every route, so when no keys
  // exist (no enforcement) every request is rejected for lack of a user.
  const clientKeys = await loadApiKeyHashes('client');
  await auth.init(clientKeys.length > 0, async () => clientKeys);
  if (clientKeys.length === 0) {
    console.warn('warning: no client API keys configured; create one with tools/add-user-key.js');
  }

  const { host, port } = getClientServiceConfig();
  const app = createApp();
  const server = http.createServer(app);

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });

  console.log(`ELA client API listening on http://${host}:${port}/`);
  console.log('Routes: GET /uploads, /uploads/:type, /uploads/:type/:id, /uploads/:type/:id/raw');

  process.on('SIGINT', () => {
    server.close(async () => {
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
