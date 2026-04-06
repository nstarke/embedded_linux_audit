'use strict';

const path = require('path');

const DEFAULT_DB_CONFIG = {
  development: {
    host: '127.0.0.1',
    port: 5432,
    database: 'embedded_linux_audit',
    username: 'ela',
    password: 'ela',
    schema: 'public',
    ssl: false,
    logging: false,
  },
  test: {
    host: '127.0.0.1',
    port: 5432,
    database: 'embedded_linux_audit_test',
    username: 'ela',
    password: 'ela',
    schema: 'public',
    ssl: false,
    logging: false,
  },
  production: {
    host: 'postgres',
    port: 5432,
    database: 'embedded_linux_audit',
    username: 'ela',
    password: 'ela',
    schema: 'public',
    ssl: false,
    logging: false,
  },
};

function currentEnvironment() {
  const value = String(process.env.NODE_ENV || 'development').trim().toLowerCase();
  return DEFAULT_DB_CONFIG[value] ? value : 'development';
}

function envKey(name, env = currentEnvironment()) {
  return `ELA_${env.toUpperCase()}_${name}`;
}

function firstDefined(keys) {
  for (const key of keys) {
    if (process.env[key] !== undefined && process.env[key] !== '') {
      return process.env[key];
    }
  }
  return undefined;
}

function parseBoolean(value, fallback) {
  if (value === undefined) {
    return fallback;
  }
  return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

function parseInteger(value, fallback) {
  const parsed = Number.parseInt(String(value), 10);
  return Number.isInteger(parsed) ? parsed : fallback;
}

function getDatabaseConfig() {
  const env = currentEnvironment();
  const defaults = DEFAULT_DB_CONFIG[env];
  const sslValue = firstDefined(['ELA_DB_SSL', envKey('DB_SSL')]);
  const sslRejectUnauthorizedValue = firstDefined(['ELA_DB_SSL_REJECT_UNAUTHORIZED', envKey('DB_SSL_REJECT_UNAUTHORIZED')]);
  const loggingValue = firstDefined(['ELA_DB_LOGGING', envKey('DB_LOGGING')]);
  const databaseUrl = firstDefined(['ELA_DATABASE_URL', envKey('DATABASE_URL')]);

  return {
    env,
    dialect: 'postgres',
    url: databaseUrl || null,
    host: firstDefined(['ELA_DB_HOST', envKey('DB_HOST')]) || defaults.host,
    port: parseInteger(firstDefined(['ELA_DB_PORT', envKey('DB_PORT')]), defaults.port),
    database: firstDefined(['ELA_DB_NAME', 'ELA_DB_DATABASE', envKey('DB_NAME'), envKey('DB_DATABASE')]) || defaults.database,
    username: firstDefined(['ELA_DB_USER', 'ELA_DB_USERNAME', envKey('DB_USER'), envKey('DB_USERNAME')]) || defaults.username,
    password: firstDefined(['ELA_DB_PASSWORD', envKey('DB_PASSWORD')]) || defaults.password,
    schema: firstDefined(['ELA_DB_SCHEMA', envKey('DB_SCHEMA')]) || defaults.schema,
    ssl: parseBoolean(sslValue, defaults.ssl),
    sslRejectUnauthorized: parseBoolean(sslRejectUnauthorizedValue, true),
    logging: parseBoolean(loggingValue, defaults.logging),
  };
}

function getAgentServiceConfig() {
  return {
    host: process.env.ELA_AGENT_HOST || '0.0.0.0',
    port: parseInteger(process.env.ELA_AGENT_PORT, 5000),
    logPrefix: process.env.ELA_AGENT_LOG_PREFIX || 'post_requests',
    dataDir: process.env.ELA_AGENT_DATA_DIR || 'api/agent/data',
    repo: process.env.ELA_AGENT_REPO || 'nstarke/embedded_linux_audit',
    assetsDir: process.env.ELA_AGENT_ASSETS_DIR || null,
    testsDir: process.env.ELA_AGENT_TESTS_DIR || 'tests',
  };
}

function getTerminalServiceConfig() {
  return {
    host: process.env.ELA_TERMINAL_HOST || '0.0.0.0',
    port: parseInteger(process.env.ELA_TERMINAL_PORT, 8080),
    keyPath: process.env.ELA_KEY_PATH || path.join(__dirname, '..', '..', 'ela.key'),
  };
}

module.exports = {
  currentEnvironment,
  getDatabaseConfig,
  getAgentServiceConfig,
  getTerminalServiceConfig,
};
