'use strict';

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

function loadMigrate({ initializeResult, migrationResult, initializeError, migrationError, closeError } = {}) {
  jest.resetModules();

  const initializeDatabase = jest.fn(() => initializeError ? Promise.reject(initializeError) : Promise.resolve(initializeResult));
  const runMigrations = jest.fn(() => migrationError ? Promise.reject(migrationError) : Promise.resolve(migrationResult));
  const closeDatabase = jest.fn(() => closeError ? Promise.reject(closeError) : Promise.resolve());
  const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  const exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => undefined);

  jest.doMock('../../../../api/lib/db/index', () => ({
    initializeDatabase,
    runMigrations,
    closeDatabase,
  }));

  require('../../../../api/lib/db/migrate');

  return { initializeDatabase, runMigrations, closeDatabase, logSpy, errorSpy, exitSpy };
}

describe('db migrate entrypoint', () => {
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  test('logs applied migrations and closes the database on success', async () => {
    const { initializeDatabase, runMigrations, closeDatabase, logSpy, errorSpy, exitSpy } = loadMigrate({
      migrationResult: [{ name: '0001-init' }, { name: '0002-extra' }],
    });

    await flush();
    await flush();

    expect(initializeDatabase).toHaveBeenCalledTimes(1);
    expect(runMigrations).toHaveBeenCalledTimes(1);
    expect(closeDatabase).toHaveBeenCalledTimes(1);
    expect(logSpy).toHaveBeenCalledWith('Applied migration: 0001-init');
    expect(logSpy).toHaveBeenCalledWith('Applied migration: 0002-extra');
    expect(errorSpy).not.toHaveBeenCalled();
    expect(exitSpy).not.toHaveBeenCalled();
  });

  test('logs when there are no pending migrations', async () => {
    const { closeDatabase, logSpy } = loadMigrate({
      migrationResult: [],
    });

    await flush();
    await flush();

    expect(logSpy).toHaveBeenCalledWith('No pending migrations');
    expect(closeDatabase).toHaveBeenCalledTimes(1);
  });

  test('logs errors, closes the database, and exits with code 1 on failure', async () => {
    const failure = new Error('boom');
    failure.stack = 'boom-stack';
    const { closeDatabase, errorSpy, exitSpy } = loadMigrate({
      migrationError: failure,
    });

    await flush();
    await flush();

    expect(errorSpy).toHaveBeenCalledWith('boom-stack');
    expect(closeDatabase).toHaveBeenCalledTimes(1);
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  test('still exits when closeDatabase also fails during error handling', async () => {
    const failure = new Error('init failed');
    failure.stack = 'init-stack';
    const { errorSpy, exitSpy } = loadMigrate({
      initializeError: failure,
      closeError: new Error('close failed'),
    });

    await flush();
    await flush();

    expect(errorSpy).toHaveBeenCalledWith('init-stack');
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});
