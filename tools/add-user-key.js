#!/usr/bin/env node
// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

/**
 * Add a user and API key to the database.
 *
 * Usage:
 *   node tools/add-user-key.js --username <username> [--label <label>] [--key <plaintext-key>]
 *
 * If --key is omitted a cryptographically random 32-byte hex key is generated.
 * The plaintext key is printed once and never stored — only its SHA-256 hash
 * is written to the database.
 */

const path = require('path');
const crypto = require('crypto');

// Resolve DB modules relative to the repo root so the script can be run
// from any working directory.
const repoRoot = path.resolve(__dirname, '..');
const { initializeDatabase, runMigrations, closeDatabase } = require(path.join(repoRoot, 'api/lib/db'));
const { createApiKey } = require(path.join(repoRoot, 'api/lib/db/deviceRegistry'));

function getArg(flag) {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 ? process.argv[idx + 1] : null;
}

const username = getArg('--username');
const label = getArg('--label') || null;
const providedKey = getArg('--key');

if (!username) {
  process.stderr.write('usage: add-user-key.js --username <username> [--label <label>] [--key <plaintext-key>]\n');
  process.exit(1);
}

async function main() {
  const plaintextKey = providedKey || crypto.randomBytes(32).toString('hex');
  const keyHash = crypto.createHash('sha256').update(plaintextKey, 'utf8').digest('hex');

  await initializeDatabase();
  await runMigrations();

  const { created } = await createApiKey(username, keyHash, label);

  await closeDatabase();

  if (!created) {
    process.stderr.write('error: a key with the same value already exists\n');
    process.exit(1);
  }

  process.stdout.write(`username: ${username}\n`);
  if (label) process.stdout.write(`label:    ${label}\n`);
  process.stdout.write(`key:      ${plaintextKey}\n`);
  process.stdout.write('\nStore this key securely — it will not be shown again.\n');
}

main().catch((err) => {
  process.stderr.write(`error: ${err.message}\n`);
  closeDatabase().catch(() => {}).finally(() => process.exit(1));
});
