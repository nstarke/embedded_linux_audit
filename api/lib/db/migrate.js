#!/usr/bin/env node
'use strict';

const { initializeDatabase, runMigrations, closeDatabase } = require('./index');

async function main() {
  await initializeDatabase();
  const migrations = await runMigrations();
  if (migrations.length === 0) {
    console.log('No pending migrations');
  } else {
    for (const migration of migrations) {
      console.log(`Applied migration: ${migration.name}`);
    }
  }
}

main()
  .then(async () => {
    await closeDatabase();
  })
  .catch(async (err) => {
    console.error(err.stack || err.message);
    try {
      await closeDatabase();
    } catch (_) {
      // ignore shutdown errors
    }
    process.exit(1);
  });
