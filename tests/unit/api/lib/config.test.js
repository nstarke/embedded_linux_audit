'use strict';

const ENV_KEYS = [
  'NODE_ENV',
  'ELA_DB_SSL',
  'ELA_TEST_DB_SSL',
  'ELA_DB_LOGGING',
  'ELA_TEST_DB_LOGGING',
  'ELA_DATABASE_URL',
  'ELA_TEST_DATABASE_URL',
  'ELA_DB_HOST',
  'ELA_TEST_DB_HOST',
  'ELA_DB_PORT',
  'ELA_TEST_DB_PORT',
  'ELA_DB_NAME',
  'ELA_DB_DATABASE',
  'ELA_TEST_DB_NAME',
  'ELA_TEST_DB_DATABASE',
  'ELA_DB_USER',
  'ELA_DB_USERNAME',
  'ELA_TEST_DB_USER',
  'ELA_TEST_DB_USERNAME',
  'ELA_DB_PASSWORD',
  'ELA_TEST_DB_PASSWORD',
  'ELA_DB_SCHEMA',
  'ELA_TEST_DB_SCHEMA',
  'ELA_AGENT_HOST',
  'ELA_AGENT_PORT',
  'ELA_AGENT_LOG_PREFIX',
  'ELA_AGENT_DATA_DIR',
  'ELA_AGENT_REPO',
  'ELA_AGENT_ASSETS_DIR',
  'ELA_AGENT_TESTS_DIR',
  'ELA_TERMINAL_HOST',
  'ELA_TERMINAL_PORT',
  'ELA_KEY_PATH',
];

function clearEnv() {
  for (const key of ENV_KEYS) {
    delete process.env[key];
  }
}

describe('api config', () => {
  beforeEach(() => {
    jest.resetModules();
    clearEnv();
  });

  afterAll(() => {
    clearEnv();
  });

  test('uses development defaults when NODE_ENV is unknown', () => {
    process.env.NODE_ENV = 'staging';
    const config = require('../../../../api/lib/config');

    expect(config.currentEnvironment()).toBe('development');
    expect(config.getDatabaseConfig()).toEqual(expect.objectContaining({
      env: 'development',
      host: '127.0.0.1',
      port: 5432,
      database: 'embedded_linux_audit',
      username: 'ela',
      password: 'ela',
      schema: 'public',
      ssl: false,
      logging: false,
      url: null,
    }));
  });

  test('applies environment-specific database overrides and parses booleans and integers', () => {
    process.env.NODE_ENV = 'test';
    process.env.ELA_TEST_DB_HOST = 'db.internal';
    process.env.ELA_TEST_DB_PORT = '6543';
    process.env.ELA_TEST_DB_NAME = 'ela_test_db';
    process.env.ELA_TEST_DB_USER = 'ela_user';
    process.env.ELA_TEST_DB_PASSWORD = 'secret';
    process.env.ELA_TEST_DB_SCHEMA = 'audit';
    process.env.ELA_TEST_DB_SSL = 'yes';
    process.env.ELA_TEST_DB_LOGGING = 'on';

    const config = require('../../../../api/lib/config');

    expect(config.getDatabaseConfig()).toEqual(expect.objectContaining({
      env: 'test',
      host: 'db.internal',
      port: 6543,
      database: 'ela_test_db',
      username: 'ela_user',
      password: 'secret',
      schema: 'audit',
      ssl: true,
      logging: true,
    }));
  });

  test('global database env vars take precedence over environment-specific vars', () => {
    process.env.NODE_ENV = 'test';
    process.env.ELA_TEST_DB_HOST = 'db.internal';
    process.env.ELA_DB_HOST = 'db.global';
    process.env.ELA_TEST_DB_PORT = '6543';
    process.env.ELA_DB_PORT = '7000';
    process.env.ELA_TEST_DATABASE_URL = 'postgres://env-specific';
    process.env.ELA_DATABASE_URL = 'postgres://global';

    const config = require('../../../../api/lib/config');
    const db = config.getDatabaseConfig();

    expect(db.host).toBe('db.global');
    expect(db.port).toBe(7000);
    expect(db.url).toBe('postgres://global');
  });

  test('falls back on invalid integer and falsey boolean parsing', () => {
    process.env.NODE_ENV = 'test';
    process.env.ELA_DB_PORT = 'not-a-number';
    process.env.ELA_DB_SSL = 'false';
    process.env.ELA_DB_LOGGING = '0';

    const config = require('../../../../api/lib/config');
    const db = config.getDatabaseConfig();

    expect(db.port).toBe(5432);
    expect(db.ssl).toBe(false);
    expect(db.logging).toBe(false);
  });

  test('returns configured agent and terminal service settings', () => {
    process.env.ELA_AGENT_HOST = '127.0.0.1';
    process.env.ELA_AGENT_PORT = '5100';
    process.env.ELA_AGENT_LOG_PREFIX = 'uploads';
    process.env.ELA_AGENT_DATA_DIR = '/tmp/data';
    process.env.ELA_AGENT_REPO = 'org/repo';
    process.env.ELA_AGENT_ASSETS_DIR = '/tmp/assets';
    process.env.ELA_AGENT_TESTS_DIR = '/tmp/tests';
    process.env.ELA_TERMINAL_HOST = '127.0.0.2';
    process.env.ELA_TERMINAL_PORT = '9090';
    process.env.ELA_KEY_PATH = '/tmp/ela.key';

    const config = require('../../../../api/lib/config');

    expect(config.getAgentServiceConfig()).toEqual({
      host: '127.0.0.1',
      port: 5100,
      logPrefix: 'uploads',
      dataDir: '/tmp/data',
      repo: 'org/repo',
      assetsDir: '/tmp/assets',
      testsDir: '/tmp/tests',
    });
    expect(config.getTerminalServiceConfig()).toEqual({
      host: '127.0.0.2',
      port: 9090,
      keyPath: '/tmp/ela.key',
    });
  });
});
